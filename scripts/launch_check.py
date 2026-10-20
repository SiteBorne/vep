"""Launch gate: run real checks, record evidence pointers, compute readiness levels by fixed rules.

    python scripts/launch_check.py [--out launch-gate.json] [--report docs/LAUNCH_READINESS_REPORT.md] [--skip-slow]

Statuses: PASS | FAIL | NOT_RUN | UNVERIFIED | NOT_APPLICABLE. A required category can never pass by being NOT_APPLICABLE,
a missing tool yields NOT_RUN, and every PASS carries evidence: commands executed now (exit code and output digest),
and/or files with SHA-256. Existing reports are accepted as evidence only if the evaluation-critical source has not
changed since the commit that produced them.

Levels (rules are data below, not judgement):
  LOCAL_BETA_READY, PUBLIC_BETA_READY, UNTRUSTED_EXECUTION_READY, PRODUCTION_READY.
ANNOUNCEMENT_READY = (PUBLIC_BETA_READY).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts" / "release"))

TARGET_VERSION = "0.5.0b1"
CATEGORIES = ["CORE_PROTOCOL", "SOURCE_INTEGRITY", "CANDIDATE_LIFECYCLE", "EXECUTION_CONTROLLER", "RESOURCE_ACCOUNTING",
              "BUILD_INTEGRATION", "EVIDENCE_INTEGRITY", "CERTIFICATE_VERIFICATION", "AGENT_INTEGRATION", "CONCURRENCY",
              "COMPOSITE_VERIFICATION", "PROTOCOL_CONFORMANCE", "REAL_WORLD_DOGFOOD", "BENCHMARK_REPRODUCIBILITY", "SECURITY",
              "ISOLATION", "DOCUMENTATION", "PACKAGING", "SUPPLY_CHAIN", "PUBLIC_QUICKSTART", "ANNOUNCEMENT_CLAIMS"]
LEVELS = {
    "LOCAL_BETA_READY": {"categories": ["CORE_PROTOCOL", "SOURCE_INTEGRITY", "CANDIDATE_LIFECYCLE", "EXECUTION_CONTROLLER",
                                        "RESOURCE_ACCOUNTING", "BUILD_INTEGRATION", "EVIDENCE_INTEGRITY", "CERTIFICATE_VERIFICATION",
                                        "AGENT_INTEGRATION", "CONCURRENCY", "COMPOSITE_VERIFICATION", "PROTOCOL_CONFORMANCE",
                                        "REAL_WORLD_DOGFOOD", "SECURITY", "DOCUMENTATION", "PACKAGING", "PUBLIC_QUICKSTART"],
                         "conditions": []},
    "PUBLIC_BETA_READY": {"requires_level": "LOCAL_BETA_READY",
                          "categories": ["BENCHMARK_REPRODUCIBILITY", "SUPPLY_CHAIN", "ANNOUNCEMENT_CLAIMS"],
                          "conditions": ["version_is_target", "working_tree_clean", "head_pushed", "hosted_ci_green_for_head"]},
    "UNTRUSTED_EXECUTION_READY": {"requires_level": "PUBLIC_BETA_READY", "categories": ["ISOLATION"],
                                  "conditions": ["external_security_review", "escape_testing", "in_container_runtime_corroboration"]},
    "PRODUCTION_READY": {"requires_level": "UNTRUSTED_EXECUTION_READY", "categories": [],
                         "conditions": ["production_criteria_defined_and_met"]},
}
# Test files that substantiate each category (all must run, none fail, none skip).
TESTS = {
    "CORE_PROTOCOL": ["test_canonical", "test_storage", "test_snapshots", "test_compat", "test_math", "test_policies"],
    "CANDIDATE_LIFECYCLE": ["test_candidates", "test_integration", "test_git"],
    "EXECUTION_CONTROLLER": ["test_controller"],
    "RESOURCE_ACCOUNTING": ["test_budgets", "test_tokens", "test_cache", "test_routing", "test_context"],
    "BUILD_INTEGRATION": ["test_builds", "test_cli_build"],
    "EVIDENCE_INTEGRITY": ["test_execution", "test_adversarial", "test_audits"],
    "CERTIFICATE_VERIFICATION": ["test_certificates", "test_trust"],
    "AGENT_INTEGRATION": ["test_agents"],
    "CONCURRENCY": ["test_controller"],
    "COMPOSITE_VERIFICATION": ["test_depgraph"],
    "SECURITY": ["test_hardening", "test_adversarial", "test_isolation", "test_isolation_matrix"],
}
CRITICAL_SRC = ["src/vep/_runner.py", "src/vep/execution.py", "src/vep/policies.py", "src/vep/snapshots.py", "src/vep/certificates.py",
                "src/vep/controller.py", "src/vep/evidence.py", "src/vep/objects.py", "src/vep/canonical.py", "src/vep/storage.py",
                "src/vep/database.py", "src/vep/budgets.py", "src/vep/candidates.py", "src/vep/conformance.py"]
REQUIRED_DOCS = ["README.md", "docs/ANNOUNCEMENT.md", "docs/WHY_VEP.md", "docs/COMPARISON.md", "docs/QUICKSTART.md",
                 "docs/REAL_WORLD_RESULTS.md", "docs/BENCHMARK_METHODOLOGY.md", "docs/SECURITY_LIMITATIONS.md", "docs/ROADMAP.md",
                 "docs/FAQ.md", "docs/REAL_WORLD_BASELINE.md", "docs/IMPLEMENTATION_PROGRESS.md", "docs/CONFORMANCE.md",
                 "docs/CONTROLLER_SCALING.md", "CHANGELOG.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SUPPORT.md"]
PY = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(argv, timeout=900, cwd=ROOT, env=None) -> dict:
    try:
        r = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        out = r.stdout + r.stderr
        return {"argv": [os.path.basename(argv[0]) if i == 0 else a for i, a in enumerate(argv)], "exit_code": r.returncode,
                "output_sha256": hashlib.sha256(out.encode()).hexdigest(), "tail": out.strip().splitlines()[-3:], "_out": out}
    except FileNotFoundError as exc:
        return {"argv": [str(argv[0])], "exit_code": None, "error": str(exc), "tail": [], "_out": ""}
    except subprocess.TimeoutExpired:
        return {"argv": [str(argv[0])], "exit_code": None, "error": "timeout", "tail": [], "_out": ""}


def git(*a) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True).stdout.strip()


def cat(status: str, **kw) -> dict:
    return {"status": status, **kw}


def file_ev(*paths) -> list[dict]:
    return [{"path": p, "sha256": sha256_file(ROOT / p)} for p in paths if (ROOT / p).exists()]


def strip(c: dict) -> dict:
    c = dict(c)
    c.pop("_out", None)
    return c


def report_is_fresh(tool_commit: str) -> tuple[bool, str]:
    if not tool_commit or subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", tool_commit], capture_output=True).returncode:
        return False, "producing commit unknown to this repository"
    d = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", tool_commit, "HEAD", "--", *CRITICAL_SRC])
    return d.returncode == 0, ("evaluation-critical source unchanged since the report" if d.returncode == 0
                               else f"evaluation-critical source changed since {tool_commit[:8]}")


def compute_levels(C: dict, conds: dict) -> tuple[dict, dict]:
    """Pure rule evaluation: a level is ready only if its prerequisite level, every listed category is PASS, and every condition holds."""
    levels, reasons = {}, {}
    for name, rule in LEVELS.items():
        why = []
        if "requires_level" in rule and not levels[rule["requires_level"]]:
            why.append(f"requires {rule['requires_level']}")
        why += [f"{c}={C[c]['status']}" for c in rule["categories"] if C[c]["status"] != "PASS"]
        why += [f"condition not met: {c}" for c in rule["conditions"] if not conds[c]]
        levels[name], reasons[name] = not why, why
    return levels, reasons


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "launch-gate.json"))
    ap.add_argument("--report", default=str(ROOT / "docs" / "LAUNCH_READINESS_REPORT.md"))
    ap.add_argument("--skip-slow", action="store_true", help="skip build/clean-room (marks them NOT_RUN)")
    a = ap.parse_args()
    head = git("rev-parse", "HEAD")
    gate: dict = {"gate_version": 1, "source_commit": head, "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                  "tracked_changes": git("status", "--porcelain", "--untracked-files=no").splitlines(), "categories": {}}
    from vep import versions
    gate["package_version"], gate["protocol_version"] = versions.PACKAGE_VERSION, versions.PROTOCOL_VERSION
    gate["target_version"] = TARGET_VERSION
    C = gate["categories"]

    # ---- one real test run, results mapped to categories
    junit = Path(tempfile.mkdtemp()) / "junit.xml"
    pytest_run = run([PY, "-m", "pytest", "-q", f"--junitxml={junit}", "-p", "no:cacheprovider"], timeout=1500)
    by_file: dict[str, dict] = defaultdict(lambda: {"tests": 0, "bad": 0, "skipped": 0})
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    if junit.exists():
        for tc in ET.parse(junit).getroot().iter("testcase"):
            f = tc.get("classname", "").split(".")[1] if tc.get("classname", "").startswith("tests.") else tc.get("classname", "")
            kids = {k.tag for k in tc}
            rec = by_file[f]
            rec["tests"] += 1
            totals["tests"] += 1
            if "failure" in kids or "error" in kids:
                rec["bad"] += 1
                totals["failures" if "failure" in kids else "errors"] += 1
            if "skipped" in kids:
                rec["skipped"] += 1
                totals["skipped"] += 1
    unittest_run = run([PY, "-m", "unittest", "discover", "-s", "tests", "-t", "."], timeout=1500)
    m = re.search(r"Ran (\d+) tests?", unittest_run["_out"])
    gate["test_totals"] = {"pytest": totals, "unittest_ran": int(m.group(1)) if m else None, "unittest_exit": unittest_run["exit_code"],
                           "pytest_exit": pytest_run["exit_code"]}

    def from_tests(name: str, extra_ok=True, extra=None) -> dict:
        files = TESTS[name]
        missing = [f for f in files if f not in by_file or by_file[f]["tests"] == 0]
        bad = {f: by_file[f] for f in files if f in by_file and (by_file[f]["bad"] or by_file[f]["skipped"])}
        if pytest_run["exit_code"] is None:
            return cat("NOT_RUN", reason="pytest unavailable")
        if missing or bad:
            return cat("FAIL", reason=f"missing={missing} bad_or_skipped={bad}", evidence={"commands": [strip(pytest_run)]})
        n = sum(by_file[f]["tests"] for f in files)
        ev = {"commands": [strip(pytest_run)], "test_files": {f: by_file[f]["tests"] for f in files}, "tests_executed": n}
        if extra:
            ev.update(extra)
        return cat("PASS" if extra_ok else "UNVERIFIED", evidence=ev)

    C["CORE_PROTOCOL"] = from_tests("CORE_PROTOCOL")
    if C["CORE_PROTOCOL"]["status"] == "PASS" and (unittest_run["exit_code"] != 0 or pytest_run["exit_code"] != 0):
        C["CORE_PROTOCOL"] = cat("FAIL", reason="full suite not green", evidence={"commands": [strip(pytest_run), strip(unittest_run)]})
    elif C["CORE_PROTOCOL"]["status"] == "PASS":
        C["CORE_PROTOCOL"]["evidence"]["commands"].append(strip(unittest_run))
    for name in ("CANDIDATE_LIFECYCLE", "EXECUTION_CONTROLLER", "RESOURCE_ACCOUNTING", "BUILD_INTEGRATION", "EVIDENCE_INTEGRITY",
                 "CERTIFICATE_VERIFICATION", "COMPOSITE_VERIFICATION", "SECURITY"):
        C[name] = from_tests(name)
    C["CONCURRENCY"] = from_tests("CONCURRENCY", extra={"files": file_ev("benchmarks/results/controller_scaling.json", "docs/CONTROLLER_SCALING.md"),
                                                         "limit": "1-16 worker processes on one host; no distributed claim"})
    C["AGENT_INTEGRATION"] = from_tests("AGENT_INTEGRATION", extra={
        "files": file_ev("docs/live_agent_run.json"),
        "limit": "adapter protocol tested; ONE live local-model run (qwen2.5-coder:7b), interactive authorship of the dogfood change, no autonomous-agent dogfood"})

    # ---- source integrity
    ci = run([PY, "scripts/release/ci_checks.py"])
    clean = not gate["tracked_changes"]
    C["SOURCE_INTEGRITY"] = cat("PASS" if ci["exit_code"] == 0 else "FAIL", evidence={"commands": [strip(ci)], "commit": head,
                                "tracked_tree_clean": clean, "note": "static checks: secrets in tree and history, workflows, claims, versions"})

    # ---- conformance
    conf = run(["bash", "scripts/conformance_check.sh"]) if shutil.which("node") else {"exit_code": None}
    if not shutil.which("node"):
        C["PROTOCOL_CONFORMANCE"] = cat("NOT_RUN", reason="node not installed; independent verifier cannot run")
    else:
        ok = conf["exit_code"] == 0 and re.search(r"(\d+)/\1 vectors agree", conf["_out"]) is not None
        C["PROTOCOL_CONFORMANCE"] = cat("PASS" if ok else "FAIL", evidence={"commands": [strip(conf)], "files": file_ev("conformance/vectors/suite-1.0.json", "docs/CONFORMANCE.md")})

    # ---- real-world reports (fresh only)
    rw_ev, rw_ok, notes = [], True, []
    for path, tool_key in (("docs/dogfood/vep-on-vep-run-4-final-runner.json", ("tool", "tool_commit")),
                           ("docs/external/pyflakes.json", ("tool", "vep_commit")), ("docs/external/more-itertools.json", ("tool", "vep_commit"))):
        d = json.loads((ROOT / path).read_text())
        commit = d[tool_key[0]][tool_key[1]]
        fresh, why = report_is_fresh(commit)
        passed = d.get("outcome") == "DOGFOOD_PASS" or (isinstance(d.get("outcome"), dict) and d["outcome"].get("all_expected") is True)
        rw_ev.append({"path": path, "sha256": sha256_file(ROOT / path), "producing_commit": commit, "fresh": fresh, "why": why, "outcome_pass": passed})
        rw_ok &= fresh and passed
    C["REAL_WORLD_DOGFOOD"] = cat("PASS" if rw_ok else "UNVERIFIED", evidence={"reports": rw_ev},
                                  limits=["trusted-local only", "VEP change authored interactively", "two small projects without third-party dependencies"])

    # ---- benchmark reproducibility
    bm = {}
    for p in ("benchmarks/results/compare-pyflakes.json", "benchmarks/results/compare-more-itertools.json"):
        d = json.loads((ROOT / p).read_text())
        bm[p] = {"sha256": sha256_file(ROOT / p), "load_avg_1m_at_start": round(d["host"]["load_avg_1m_at_start"], 2),
                 "gate_failures": d["gate_failures"]}
    idle = all(v["load_avg_1m_at_start"] < 2.0 and not v["gate_failures"] for v in bm.values())
    C["BENCHMARK_REPRODUCIBILITY"] = cat("PASS" if idle else "UNVERIFIED", evidence={"reports": bm, "methodology": file_ev("docs/BENCHMARK_METHODOLOGY.md")},
                                         reason=None if idle else "benchmarks were measured on a machine that was not idle (declared deviation); re-run on a quiet machine required")

    # ---- isolation (hosted runner evidence only)
    att = json.loads((ROOT / "docs/isolation/ci-run-39347549501-attestation.json").read_text())
    e2e = json.loads((ROOT / "docs/isolation/ci-run-39347549501-e2e-summary.json").read_text())
    iso_ok = att["status"] == "ISOLATED_VERIFIED" and all(r["status"] == "PASS" for r in att["results"].values()) and e2e["result"] == "PASS"
    probe = run([PY, "-m", "vep.cli", "isolation", "probe", "--json"])
    C["ISOLATION"] = cat("PASS" if iso_ok else "FAIL", evidence={"files": file_ev("docs/isolation/ci-run-39347549501-attestation.json", "docs/isolation/ci-run-39347549501-e2e-summary.json", ".github/workflows/isolation.yml"),
                                                                "hosted_runs": ["github.com/SiteBorne/vep/actions/runs/39347549501 (pass)", "39347349190 (failed closed; bug fixed)"],
                                                                "local_probe": {"exit_code": probe["exit_code"], "tail": probe["tail"]}},
                         limits=["one hosted-runner run", "not escape-tested", "T12 is docker-inspect-only", "this machine: ISOLATION_UNVERIFIED"])

    # ---- documentation, claims
    missing = [d for d in REQUIRED_DOCS if not (ROOT / d).exists() and d != "docs/LAUNCH_READINESS_REPORT.md"]
    broken = []
    for md in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", md.read_text()):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            if not (md.parent / target).resolve().exists():
                broken.append(f"{md.relative_to(ROOT)} -> {target}")
    reg = run([PY, "scripts/gen_variables.py", "--check"])
    C["DOCUMENTATION"] = cat("PASS" if not missing and not broken and reg["exit_code"] == 0 else "FAIL",
                             evidence={"required_docs_missing": missing, "broken_relative_links": broken[:10], "commands": [strip(reg)]})
    claims = run([PY, "scripts/check_claims.py"])
    scan = ci  # ci_checks.py includes the forbidden-claims scan over README, SECURITY, CHANGELOG and docs/*.md
    posted = "NOTHING HAS BEEN POSTED" in (ROOT / "docs/ANNOUNCEMENT.md").read_text()
    C["ANNOUNCEMENT_CLAIMS"] = cat("PASS" if claims["exit_code"] == 0 and scan["exit_code"] == 0 and posted else "FAIL",
                                   evidence={"commands": [strip(claims), strip(scan)], "announcement_marked_unposted": posted,
                                             "files": file_ev("docs/claims.json", "docs/ANNOUNCEMENT.md")})

    # ---- packaging, supply chain, clean-room quickstart
    dist = Path(tempfile.mkdtemp())
    if a.skip_slow:
        C["PACKAGING"] = cat("NOT_RUN", reason="--skip-slow")
        C["PUBLIC_QUICKSTART"] = cat("NOT_RUN", reason="--skip-slow")
    else:
        build = run([PY, "-m", "build", "--outdir", str(dist)], timeout=900)
        arts = sorted(dist.glob("*"))
        tw = run([PY, "-m", "twine", "check", "--strict", *map(str, arts)]) if arts else {"exit_code": None}
        art_ev = [{"name": p.name, "sha256": sha256_file(p), "bytes": p.stat().st_size} for p in arts]
        C["PACKAGING"] = cat("PASS" if build["exit_code"] == 0 and len(arts) == 2 and tw["exit_code"] == 0 else "FAIL",
                             evidence={"artifacts": art_ev, "commands": [strip(build), strip(tw)],
                                       "note": "built from this commit; version is still the pre-bump value, see conditions"})
        wheels = [p for p in arts if p.suffix == ".whl"]
        if not wheels:
            C["PUBLIC_QUICKSTART"] = cat("NOT_RUN", reason="no wheel built")
        else:
            venv = Path(tempfile.mkdtemp()) / "v"
            mk = run([sys.executable, "-m", "venv", str(venv)])
            ins = run([str(venv / "bin" / "pip"), "install", "-q", str(wheels[0])], timeout=600)
            if ins["exit_code"] != 0:
                C["PUBLIC_QUICKSTART"] = cat("NOT_RUN", reason="wheel could not be installed (network or dependency problem)", evidence={"commands": [strip(ins)]})
            else:
                cr = run([PY, "scripts/release/cleanroom.py", "--venv", str(venv)], timeout=600)
                qs = run([PY, "scripts/release/quickstart_runner.py", "--bin-dir", str(venv / "bin")], timeout=600)
                C["PUBLIC_QUICKSTART"] = cat("PASS" if cr["exit_code"] == 0 and qs["exit_code"] == 0 else "FAIL",
                                             evidence={"commands": [strip(mk), strip(ins), strip(cr), strip(qs)], "installed_wheel": wheels[0].name})
    wf = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    C["SUPPLY_CHAIN"] = cat("PASS" if ci["exit_code"] == 0 and (ROOT / ".github/dependabot.yml").exists() and wf else "FAIL",
                            evidence={"commands": [strip(ci)], "workflows": [w.name for w in wf], "files": file_ev(".github/dependabot.yml"),
                                      "runtime_dependencies": ["cryptography>=41"]},
                            limits=["static workflow lint only; hosted CI/CodeQL results for this commit are NOT_RUN (unpushed)",
                                    "no SLSA level claimed"])

    for c in CATEGORIES:
        if c not in C:
            C[c] = cat("NOT_RUN", reason="no check implemented")
        if C[c]["status"] == "NOT_APPLICABLE":
            C[c] = cat("FAIL", reason="required category cannot be NOT_APPLICABLE")
        if C[c]["status"] == "PASS" and not C[c].get("evidence"):
            C[c] = cat("FAIL", reason="PASS without evidence")

    # ---- level conditions (manual-evidence items are NOT_RUN unless recorded)
    remote = git("ls-remote", "origin", "HEAD") if shutil.which("git") else ""
    pushed = bool(remote) and remote.split()[0] == head
    conds = {"version_is_target": gate["package_version"] == TARGET_VERSION, "working_tree_clean": clean, "head_pushed": pushed,
             "hosted_ci_green_for_head": False,  # requires a pushed commit with green CI; none exists for HEAD
             "external_security_review": False, "escape_testing": False, "in_container_runtime_corroboration": False,
             "production_criteria_defined_and_met": False}
    gate["conditions"] = {k: {"met": v, "evidence": ("computed now" if k in ("version_is_target", "working_tree_clean", "head_pushed") else "none recorded: NOT_RUN")} for k, v in conds.items()}
    levels, reasons = compute_levels(C, conds)
    gate["levels"] = {k: {"ready": levels[k], "blocking": reasons[k]} for k in LEVELS}
    gate["ANNOUNCEMENT_READY"] = "YES" if levels["PUBLIC_BETA_READY"] else "NO"
    gate["artifacts"] = C["PACKAGING"].get("evidence", {}).get("artifacts", [])
    Path(a.out).write_text(json.dumps(gate, indent=1, sort_keys=True, default=str) + "\n")
    write_report(gate, Path(a.report))
    print(json.dumps({"ANNOUNCEMENT_READY": gate["ANNOUNCEMENT_READY"], "levels": {k: v["ready"] for k, v in gate["levels"].items()},
                      "categories": {k: v["status"] for k, v in C.items()}}, indent=1))
    return 0


def write_report(g: dict, path: Path) -> None:
    C = g["categories"]
    t = g["test_totals"]["pytest"]
    L = [f"# Launch readiness report", "",
         "Generated by `scripts/launch_check.py` from `launch-gate.json`; rules are in that script, not in prose.", "",
         f"**ANNOUNCEMENT_READY = {g['ANNOUNCEMENT_READY']}**  (rule: YES only when PUBLIC_BETA_READY)", "",
         "## Identity", f"* Source commit: `{g['source_commit']}` on `{g['branch']}`; tracked changes at run time: {len(g['tracked_changes'])}",
         f"* Package version: `{g['package_version']}` (target `{g['target_version']}`, not bumped); protocol `{g['protocol_version']}`",
         f"* Tests: pytest {t['tests']} run, {t['failures']} failed, {t['errors']} errors, {t['skipped']} skipped; unittest ran {g['test_totals']['unittest_ran']} (exit {g['test_totals']['unittest_exit']}). The count is not the headline: see the real-world rows below.", "",
         "## Readiness levels", "| Level | Ready | Blocking |", "|---|---|---|"]
    for k, v in g["levels"].items():
        L.append(f"| {k} | {'YES' if v['ready'] else 'NO'} | {'; '.join(v['blocking']) or '-'} |")
    L += ["", "## Categories", "| Category | Status | Evidence / reason |", "|---|---|---|"]
    for k, v in C.items():
        ev = v.get("evidence") or {}
        bits = []
        if "commands" in ev:
            bits.append("commands: " + ", ".join(f"`{c['argv'][0]} {' '.join(c['argv'][1:3])}`→{c['exit_code']}" for c in ev["commands"][:3]))
        if "reports" in ev:
            bits.append("reports: " + ", ".join(Path(p if isinstance(p, str) else p["path"]).name for p in (ev["reports"] if isinstance(ev["reports"], list) else ev["reports"].keys())))
        if "files" in ev:
            bits.append("files: " + ", ".join(Path(f["path"]).name for f in ev["files"][:4]))
        if v.get("reason"):
            bits.append(v["reason"])
        L.append(f"| {k} | {v['status']} | {'; '.join(bits)[:300]} |")
    L += ["", "## Real-world scenarios executed", "* VEP-on-VEP (`docs/dogfood/`, final run `vep-on-vep-run-4-final-runner.json`), pyflakes and more-itertools at pinned commits (`docs/external/`), one live local-model run (`docs/live_agent_run.json`).",
          "* Report freshness is checked mechanically against the evaluation-critical source; see `REAL_WORLD_DOGFOOD` in `launch-gate.json`.", "",
          "## Benchmark, conformance, isolation",
          "* Benchmarks: `benchmarks/results/compare-*.json`, `docs/REAL_WORLD_RESULTS.md`; **measured on a non-idle machine**, status above.",
          "* Conformance: `conformance/vectors/suite-1.0.json` run by the Python reference and the independent Node verifier (`scripts/conformance_check.sh`).",
          "* Isolation: hosted-runner runs 39347349190 (failed closed, bug fixed) and 39347549501 (pass); this machine remains `ISOLATION_UNVERIFIED`.", "",
          "## Security trust classification",
          "Default execution is `TRUSTED_LOCAL` (no isolation). `ISOLATED_VERIFIED` was observed on one hosted run, not escape-tested, no external review. Evaluating untrusted code is **not** claimed. See `docs/SECURITY_LIMITATIONS.md`.", "",
          "## Conditions", "| Condition | Met |", "|---|---|"]
    for k, v in g["conditions"].items():
        L.append(f"| {k} | {'yes' if v['met'] else 'NO'} ({v['evidence']}) |")
    L += ["", "## Release artifact hashes (built from this commit; not published)"]
    L += [f"* `{x['name']}` sha256 `{x['sha256']}` ({x['bytes']} bytes)" for x in g["artifacts"]] or ["* none built"]
    L += ["", "## CI run identifiers and publication status",
          "* Hosted: release run 39303007794 (v0.4.0a1 tag), isolation runs 39347349190 and 39347549501 on branch `isolation-ci`.",
          "* No hosted CI/CodeQL run exists for this commit; the branch is not pushed to `main`. Published: prerelease `v0.4.0a1` only. Nothing in this report has been posted anywhere.", "",
          "## Unverified or not implemented",
          "Live autonomous-agent runs; projects with third-party dependencies; Go or third verifier; remote execution (REAPI); cross-candidate evidence reuse; in-container runtime corroboration; escape testing; external audit; quiet-machine benchmark; key rotation.", ""]
    path.write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
