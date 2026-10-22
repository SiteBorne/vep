"""Machine-enforced readiness profiles. Every profile is computed from its OWN prerequisite list; no profile inherits another's result.

    python scripts/profile_check.py --run [--run-packaging] [--out docs/production-profiles.json]
    python scripts/profile_check.py --junit junit.xml            # reuse a test run you already have

A prerequisite is PASS, FAIL, or UNVERIFIED (could not be established here: missing tool, no authorization, evidence not produced). A profile is `YES`
only when every one of its prerequisites is PASS; otherwise `NO`, with the blocking prerequisites listed. Nothing is inferred from documentation text:
tests are read from a real JUnit run, vectors are executed, tools are invoked. `docs/PROFILES.md` defines the profiles; `docs/CORE_PROTOCOL_SPEC.md` §11 the Core checks.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
PASS, FAIL, UNVERIFIED = "PASS", "FAIL", "UNVERIFIED"

CORE = ["spec_present", "suites_regenerate", "python_vectors", "node_vectors", "reason_code_coverage"]
PROFILES: dict[str, list[str]] = {
    "CORE_PROTOCOL_CONFORMANT": CORE,
    "CORE_PROTOCOL_PRODUCTION_READY": CORE + ["tests_trust_anchor", "tests_reuse_chain", "tests_fault_injection", "tests_adversarial", "tests_compat_migration"],
    "REFERENCE_IMPLEMENTATION_READY": ["full_suite", "tests_fault_injection", "tests_compat_migration", "packaging_install_smoke", "installed_wheel_e2e",
                                       "sdist_contents_clean", "hosted_ci_for_head", "code_scanning_clean_for_head"],
    "MCP_STDIO_READY": ["tests_mcp_stdio", "tests_agent_sdk_contract", "mcp_remote_http_not_offered", "installed_wheel_mcp"],
    "A2A_LOOPBACK_READY": ["tests_a2a", "tests_lost_response_and_capabilities", "installed_wheel_a2a", "a2a_restart_limitation_documented"],
    "CLAUDE_PACKAGE_READY": ["tests_claude_installer", "tests_claude_installer_security", "tests_claude_live_harness", "claude_plugin_validate", "claude_client_discovery"],
    "CLAUDE_LIVE_E2E_READY": ["tests_claude_live_harness", "claude_live_tool_use"],
    "PLUGIN_DIRECTORY_PRECHECK_READY": ["tests_plugin_directory", "plugin_folder_validate", "plugin_folder_on_remote_branch"],
    "PLUGIN_PORTAL_VALIDATED": ["plugin_portal_report"],
    "RELEASE_CANDIDATE_READY": ["candidate_version_set", "implementation_frozen", "real_world_evidence_fresh", "local_gate_go_on_implementation",
                                "hosted_ci_for_head", "code_scanning_clean_for_head"],
    "RELEASE_PUBLISHED": ["release_published_and_verified"],
    "ANTHROPIC_TECHNICAL_PACKAGE_READY": ["submission_doc_complete", "submission_doc_names_commits"],
    "ANTHROPIC_DIRECTORY_SUBMISSION_READY": [],
    "UNTRUSTED_EXECUTION_READY": ["external_security_review", "escape_testing"],
    "EXTERNAL_SECURITY_REVIEW_COMPLETE": ["external_security_review"],
    "FULL_SERVICE_PRODUCTION_READY": [],
}
# Composite gates name the component profiles they depend on explicitly; they cannot exceed their weakest mandatory component.
COMPOSITE: dict[str, list[str]] = {
    "RELEASE_CANDIDATE_READY": ["CORE_PROTOCOL_PRODUCTION_READY", "REFERENCE_IMPLEMENTATION_READY", "MCP_STDIO_READY", "A2A_LOOPBACK_READY", "CLAUDE_PACKAGE_READY"],
    "ANTHROPIC_TECHNICAL_PACKAGE_READY": ["RELEASE_CANDIDATE_READY"],
    "ANTHROPIC_DIRECTORY_SUBMISSION_READY": ["RELEASE_CANDIDATE_READY", "PLUGIN_DIRECTORY_PRECHECK_READY", "PLUGIN_PORTAL_VALIDATED", "RELEASE_PUBLISHED"],
    "FULL_SERVICE_PRODUCTION_READY": ["RELEASE_CANDIDATE_READY", "ANTHROPIC_TECHNICAL_PACKAGE_READY", "RELEASE_PUBLISHED", "CLAUDE_LIVE_E2E_READY", "UNTRUSTED_EXECUTION_READY", "EXTERNAL_SECURITY_REVIEW_COMPLETE", "ANTHROPIC_DIRECTORY_SUBMISSION_READY"],
}
SCOPE = {
    "CORE_PROTOCOL_PRODUCTION_READY": "the Core Profile as specified (verification semantics, trust policy, derived attestations); says nothing about the reference implementation's hosting or hostile code",
    "MCP_STDIO_READY": "local stdio transport only; remote HTTP is not offered and no remote connector is claimed",
    "A2A_LOOPBACK_READY": "authenticated JSON-RPC on loopback by default; streaming exercised, push not offered; A2A task state is in memory and does not survive an adapter restart (the VEP job does); not qualified for public exposure",
    "CLAUDE_PACKAGE_READY": "installer, plugin layout and client discovery; says nothing about live model behaviour",
    "PLUGIN_DIRECTORY_PRECHECK_READY": "a local audit against the published checklist; it is not the portal validator",
}


def evaluate_profiles(results: dict[str, tuple[str, str]]) -> dict:
    out = {}
    for name, reqs in PROFILES.items():
        got = {r: results.get(r, (UNVERIFIED, "no check implemented")) for r in reqs}
        blocking = {r: f"{s}: {d}" for r, (s, d) in got.items() if s != PASS}
        out[name] = {"ready": "YES" if not blocking else "NO", "prerequisites": {r: {"status": s, "detail": d} for r, (s, d) in got.items()},
                     "blocking": blocking, **({"scope": SCOPE[name]} if name in SCOPE else {})}
    for name, comps in COMPOSITE.items():  # explicit dependencies; resolved in declaration order, never reading a later gate
        out[name]["requires_profiles"] = comps
        for c in comps:
            if out[c]["ready"] != "YES":
                out[name]["blocking"][f"profile {c}"] = "NO"
        out[name]["ready"] = "YES" if not out[name]["blocking"] else "NO"
    return out


# ------------------------------------------------------------------ evidence helpers
def sh(*argv: str, cwd: Path = ROOT, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True, timeout=timeout)


class Junit:
    def __init__(self, path: Path | None):
        self.cases: list[dict] = []
        if path and path.exists():
            for tc in ET.parse(path).getroot().iter("testcase"):
                status = "fail" if tc.find("failure") is not None or tc.find("error") is not None else "skip" if tc.find("skipped") is not None else "pass"
                self.cases.append({"cls": tc.get("classname", ""), "name": tc.get("name", ""), "status": status})

    def files(self, *stems: str) -> tuple[str, str]:
        if not self.cases:
            return UNVERIFIED, "no test run available (use --run or --junit)"
        notes = []
        for stem in stems:
            sel = [c for c in self.cases if c["cls"].startswith(f"tests.{stem}")]
            if not sel:
                return FAIL, f"{stem}: no tests found"
            bad = [c for c in sel if c["status"] == "fail"]
            if bad:
                return FAIL, f"{stem}: {len(bad)} failing, e.g. {bad[0]['name']}"
            skipped = [c for c in sel if c["status"] == "skip"]
            if skipped:
                return UNVERIFIED, f"{stem}: {len(skipped)} skipped (a tool is missing), e.g. {skipped[0]['name']}"
            notes.append(f"{stem}:{len(sel)}")
        return PASS, "passed " + ", ".join(notes)

    def whole(self) -> tuple[str, str]:
        if not self.cases:
            return UNVERIFIED, "no test run available"
        fails = [c for c in self.cases if c["status"] == "fail"]
        skips = [c for c in self.cases if c["status"] == "skip"]
        if fails:
            return FAIL, f"{len(fails)} failing of {len(self.cases)}"
        return PASS, f"{len(self.cases)} tests, 0 failing, {len(skips)} skipped"


def git_head() -> str:
    return sh("git", "rev-parse", "HEAD").stdout.strip()


IMPL_NONDOC = ["src", "conformance", "pyproject.toml", "MANIFEST.in", "plugins", "scripts", "tests", "benchmarks", ".github"]
IMPL_CORE = ["src", "conformance", "pyproject.toml", "MANIFEST.in", "plugins"]


def collect(junit: Junit, run_packaging: bool, evaluated: str | None = None, branch: str = "protocol/claude-native-0.6") -> dict[str, tuple[str, str]]:
    from vep import conformance, trustpolicy, versions
    R: dict[str, tuple[str, str]] = {}
    spec = ROOT / "docs" / "CORE_PROTOCOL_SPEC.md"
    R["spec_present"] = (PASS, "docs/CORE_PROTOCOL_SPEC.md") if spec.exists() and f"protocol version `{versions.PROTOCOL_VERSION}`" in spec.read_text() \
        else (FAIL, "specification missing or names another protocol version")
    gens = ["gen_conformance_vectors.py", "gen_conformance_vectors_11.py", "gen_conformance_vectors_12.py"]
    bad = [g for g in gens if sh(sys.executable, str(ROOT / "scripts" / g), "--check").returncode != 0]
    R["suites_regenerate"] = (PASS, "suites 1.0, 1.1, 1.2 regenerate byte-identically") if not bad else (FAIL, "drift in " + ", ".join(bad))
    suites = [ROOT / "conformance" / "vectors" / f"suite-1.{n}.json" for n in (0, 1, 2)]
    total, disagree = 0, []
    for s in suites:
        for v in conformance.load_suite(s)["vectors"]:
            total += 1
            if not conformance.check_vector(v, conformance.run_vector(v)):
                disagree.append(v["id"])
    R["python_vectors"] = (PASS, f"{total} vector evaluations agree") if not disagree else (FAIL, f"disagree: {disagree[:5]}")
    node = shutil.which("node")
    if not node:
        R["node_vectors"] = (UNVERIFIED, "node is not installed: the independent verifier was NOT RUN")
    else:
        lines = []
        ok = True
        for s in suites:
            r = sh(node, str(ROOT / "conformance" / "node" / "verify.mjs"), "suite", str(s))
            ok &= r.returncode == 0
            lines.append(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "no output")
        R["node_vectors"] = (PASS if ok else FAIL, "; ".join(lines))
    s12 = conformance.load_suite(suites[2])
    seen_auth = {v["expect"]["code"] for v in s12["vectors"] if v["op"] == "verify_authorized"} - {None}
    seen_der = {v["expect"]["code"] for v in s12["vectors"] if v["op"] == "verify_derived"} - {None}
    shared = {"MALFORMED_ENVELOPE", "MALFORMED_PAYLOAD", "NONCANONICAL_PAYLOAD", "WRONG_TYPE", "UNSUPPORTED_SCHEMA_VERSION", "SCHEMA_INVALID"}
    miss = (set(trustpolicy.AUTHORIZED_CODES) - shared - seen_auth) | (set(s12["derived_reason_codes"]) - {"WRONG_TYPE", "SIGNATURE_INVALID"} - seen_der)
    R["reason_code_coverage"] = (PASS, "every authorized and derived reason code has a vector") if not miss else (FAIL, f"uncovered: {sorted(miss)}")
    R["tests_trust_anchor"] = junit.files("test_trust_anchor_risk", "test_trust_policy")
    R["tests_reuse_chain"] = junit.files("test_evidence_reuse")
    R["tests_fault_injection"] = junit.files("test_fault_injection")
    R["tests_adversarial"] = junit.files("test_adversarial", "test_hardening", "test_execution")
    R["tests_compat_migration"] = junit.files("test_compat", "test_migration_fixtures", "test_candidates", "test_controller")
    R["full_suite"] = junit.whole()
    R["tests_mcp_stdio"] = junit.files("test_mcp_server")
    R["tests_agent_sdk_contract"] = junit.files("test_agent_sdk")
    R["mcp_remote_http_not_offered"] = (PASS, "vep-mcp refuses any transport but stdio (exit 2); nothing remote to qualify") \
        if sh(sys.executable, "-m", "vep.mcp_server", "--transport", "http").returncode == 2 else (FAIL, "a non-stdio transport is reachable")
    R["tests_a2a"] = junit.files("test_a2a_server")
    R["tests_lost_response_and_capabilities"] = junit.files("test_fault_injection")
    R["tests_claude_installer"] = junit.files("test_claude_code")
    claude = shutil.which("claude")
    if not claude:
        for k in ("claude_plugin_validate", "claude_client_discovery"):
            R[k] = (UNVERIFIED, "the claude CLI is not installed")
    else:
        with tempfile.TemporaryDirectory() as d:
            plug, proj = Path(d) / "plugin", Path(d) / "project"
            proj.mkdir()
            sh(sys.executable, "-m", "vep.cli", "claude", "plugin", "--out", str(plug))
            v = sh(claude, "plugin", "validate", str(plug))
            R["claude_plugin_validate"] = (PASS if v.returncode == 0 else FAIL, (v.stdout.strip().splitlines() or ["no output"])[-1])
            sh(sys.executable, "-m", "vep.cli", "claude", "install", "--root", str(proj))
            g = sh(claude, "mcp", "get", "vep", cwd=proj)
            R["claude_client_discovery"] = (PASS, "claude mcp get found the project server: " + " ".join(g.stdout.split())[:120]) if g.returncode == 0 and "Scope: Project" in g.stdout \
                else (FAIL, (g.stdout + g.stderr).strip()[:160])
    live = ROOT / "docs" / "evidence" / "claude-code-live.json"
    R["claude_live_tool_use"] = (PASS, str(live.relative_to(ROOT))) if live.exists() else (UNVERIFIED, "no recorded live Claude Code tool call: needs the user's approval of the project server and an authorized model run")
    gate = ROOT / "launch-gate.json"
    iso = (None, "")
    if gate.exists():
        g = json.loads(gate.read_text())
        lvl = g.get("levels", {})
        base = g.get("source_commit", "")
        changed = sh("git", "diff", "--name-only", f"{base}..HEAD", "--", "src/vep/isolation.py", "src/vep/_isolation_probe.py", "src/vep/_runner.py", "src/vep/execution.py",
                     ".github/workflows/isolation.yml", "docs/isolation").stdout.split()
        iso = (lvl.get("ISOLATED_EXECUTION_VERIFIED", {}).get("ready"), f"isolation-critical files changed since {base[:7]}: {changed or 'none'}")
        R["external_security_review"] = (PASS, "recorded") if lvl.get("UNTRUSTED_EXECUTION_READY", {}).get("ready") else (FAIL, "none: " + "; ".join(lvl.get("UNTRUSTED_EXECUTION_READY", {}).get("blocking", [])[:1]))
        R["escape_testing"] = (FAIL, "none recorded") if not lvl.get("UNTRUSTED_EXECUTION_READY", {}).get("ready") else (PASS, "recorded")
        R["isolation_evidence_current"] = (PASS, iso[1]) if iso[0] and not changed else (UNVERIFIED, iso[1])
    else:
        for k in ("external_security_review", "escape_testing", "isolation_evidence_current"):
            R[k] = (UNVERIFIED, "launch-gate.json missing")
    head = evaluated or git_head()
    pushed = bool(sh("git", "branch", "-r", "--contains", head).stdout.strip())
    if not pushed:
        R["hosted_ci_for_head"] = (UNVERIFIED, f"HEAD {head[:7]} is not on any remote branch: hosted CI has not run on it")
    else:
        r = sh("gh", "run", "list", "--commit", head, "--json", "workflowName,conclusion,status")
        runs = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else []
        need = {"CI", "CodeQL"}
        ok = {x["workflowName"] for x in runs if x["conclusion"] == "success"}
        R["hosted_ci_for_head"] = (PASS, f"{sorted(ok)} succeeded on {head[:7]}") if need <= ok else (UNVERIFIED, f"hosted runs for {head[:7]}: {runs or 'none'}")
    if run_packaging:
        R["packaging_install_smoke"] = packaging()
    else:
        R["packaging_install_smoke"] = (UNVERIFIED, "not executed (use --run-packaging)")
    cand = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    published = json.loads((ROOT / "release-verification.json").read_text()).get("release", {}).get("tag", "").lstrip("v") if (ROOT / "release-verification.json").exists() else None
    R["candidate_version_set"] = (PASS, cand) if cand != published else (FAIL, f"package version {cand} equals the already-published release; the next version is decided but not set")
    extra(R, junit, run_packaging, head, branch, cand)
    return R


def read_json(rel: str):
    p = ROOT / rel
    return json.loads(p.read_text()) if p.exists() else None


def extra(R: dict, junit: Junit, run_packaging: bool, head: str, branch: str, version: str) -> None:
    R["tests_claude_installer_security"] = junit.files("test_claude_code_security")
    R["tests_plugin_directory"] = junit.files("test_plugin_directory")
    R["tests_claude_live_harness"] = junit.files("test_claude_live_harness")
    e2e = read_json("docs/evidence/installed-wheel-e2e.json")
    def e2e_part(prefixes):
        if not e2e:
            return UNVERIFIED, "docs/evidence/installed-wheel-e2e.json missing (run scripts/installed_wheel_e2e.py)"
        if e2e.get("package") != version or not e2e.get("installed_from_site_packages"):
            return FAIL, "evidence is for another version or was not run from an installed wheel"
        steps = [x for x in e2e["steps"] if x["step"].split(":")[0] in prefixes]
        bad = [x["step"] for x in steps if not x["ok"]]
        return (PASS, f"{len(steps)} steps passed against the installed wheel {e2e.get('wheel')}") if steps and not bad else (FAIL, f"failed or missing: {bad or 'no steps'}")
    R["installed_wheel_mcp"] = e2e_part({"mcp", "verify"})
    R["installed_wheel_a2a"] = e2e_part({"a2a"})
    R["installed_wheel_e2e"] = (PASS, "all steps passed") if e2e and e2e.get("ok") and e2e.get("package") == version else (FAIL if e2e else UNVERIFIED, "installed-wheel e2e did not fully pass")
    a2a_doc = (ROOT / "docs" / "A2A.md").read_text().lower()
    R["a2a_restart_limitation_documented"] = (PASS, "docs/A2A.md states task state is in memory and the VEP job persists across a restart; the installed-wheel e2e checks both") \
        if "in memory" in a2a_doc and "restart" in a2a_doc else (FAIL, "A2A restart behaviour is not documented")
    if run_packaging:
        with tempfile.TemporaryDirectory() as d:
            b = sh(sys.executable, "-m", "build", "--sdist", "--outdir", d)
            tgz = next(Path(d).glob("*.tar.gz"), None)
            if b.returncode or not tgz:
                R["sdist_contents_clean"] = (FAIL, "sdist build failed")
            else:
                import tarfile
                names = tarfile.open(tgz).getnames()
                bad = [n for n in names if re.search(r"(\.pem|\.key|\.db|\.env|signing|/\.vep/|id_rsa)", n) and "/tests/fixtures/ws_v0_4_0a1/" not in n]
                has_fx = any("tests/fixtures/ws_v0_4_0a1/vep.sql" in n for n in names) and any("plugins/vep/.claude-plugin/plugin.json" in n for n in names)
                R["sdist_contents_clean"] = (PASS, f"{len(names)} members; no key, database, env or state files; fixtures and plugin folder present") if not bad and has_fx \
                    else (FAIL, f"unexpected members {bad[:3]} / fixtures+plugin present={has_fx}")
    else:
        R["sdist_contents_clean"] = (UNVERIFIED, "not executed (use --run-packaging)")
    # hosted code scanning on the evaluated commit
    cr = sh("gh", "api", f"repos/SiteBorne/vep/commits/{head}/check-runs", "--jq", '[.check_runs[]|{name,conclusion}]')
    runs = json.loads(cr.stdout) if cr.returncode == 0 and cr.stdout.strip() else []
    al = sh("gh", "api", f"repos/SiteBorne/vep/code-scanning/alerts?ref=refs/heads/{branch}&state=open", "--jq", "length")
    scan_ok = any(r["name"] == "CodeQL" and r["conclusion"] == "success" for r in runs)
    if cr.returncode or al.returncode:
        R["code_scanning_clean_for_head"] = (UNVERIFIED, "GitHub API not reachable or commit not pushed")
    else:
        R["code_scanning_clean_for_head"] = (PASS, f"check run 'CodeQL' succeeded on {head[:7]}; open alerts on the branch: {al.stdout.strip()}") if scan_ok and al.stdout.strip() == "0" \
            else (FAIL, f"CodeQL check success={scan_ok}, open alerts={al.stdout.strip()}")
    # plugin folder
    claude = shutil.which("claude")
    if claude:
        v = sh(claude, "plugin", "validate", str(ROOT / "plugins" / "vep"))
        R["plugin_folder_validate"] = (PASS if v.returncode == 0 else FAIL, "claude plugin validate plugins/vep: " + (v.stdout.strip().splitlines() or ["no output"])[-1] + " (not the directory portal's validator)")
    else:
        R["plugin_folder_validate"] = (UNVERIFIED, "the claude CLI is not installed")
    local = set(sh("git", "ls-tree", "-r", "--name-only", head, "--", "plugins/vep").stdout.split())
    remote = set(sh("git", "ls-tree", "-r", "--name-only", f"origin/{branch}", "--", "plugins/vep").stdout.split())
    R["plugin_folder_on_remote_branch"] = (PASS, f"{len(remote)} files under plugins/vep on origin/{branch}") if local and local <= remote else (UNVERIFIED, "plugins/vep is not on the remote branch yet")
    portal = read_json("docs/evidence/plugin-portal-validation.json")
    R["plugin_portal_report"] = (PASS, "portal report recorded") if portal and portal.get("blocking") == 0 else (UNVERIFIED, "PORTAL_VALIDATION=NOT_RUN: needs an authenticated claude.ai/directory/manage Validate report")
    # provenance: frozen implementation, fresh evidence, gate record
    impl = sh("git", "log", "-1", "--format=%H", head, "--", *IMPL_NONDOC).stdout.strip()
    nondoc = sh("git", "diff", "--name-only", head, "HEAD", "--", *IMPL_NONDOC).stdout.split()
    R["implementation_frozen"] = (PASS, f"IMPLEMENTATION_SHA {impl[:7]}; no non-documentation file differs between the evaluated commit {head[:7]} and HEAD") if not nondoc \
        else (FAIL, f"non-documentation files changed after the evaluated commit: {nondoc[:5]}")
    crit = load_critical()
    stale = []
    for rel in ("docs/dogfood/vep-on-vep-run-6-0.6-candidate.json", "docs/external/pyflakes-0.6-candidate.json", "docs/external/more-itertools-0.6-candidate.json"):
        rec = read_json(rel)
        pc = sh("git", "log", "-1", "--format=%H", "--", rel).stdout.strip()
        changed = sh("git", "diff", "--name-only", pc, "HEAD", "--", *crit).stdout.split() if pc else crit
        ok = rec is not None and (rec.get("outcome") == "DOGFOOD_PASS" or rec.get("outcome", {}).get("all_expected") is True) \
            and rec["verification"].get("authorized_verification", {}).get("node") == "AUTHORIZED"
        if changed or not ok:
            stale.append(f"{rel}: changed={changed[:2]} ok={ok}")
    R["real_world_evidence_fresh"] = (PASS, "VEP-on-VEP, pyflakes and more-itertools records pass, include Python+Node authorized verification, and no evaluation-critical file changed since they were produced") if not stale else (FAIL, "; ".join(stale))
    gate = read_json("docs/evidence/release-gate-summary.json")
    if not gate:
        R["local_gate_go_on_implementation"] = (UNVERIFIED, "docs/evidence/release-gate-summary.json missing")
    else:
        gd = sh("git", "diff", "--name-only", gate["source_commit"], "HEAD", "--", *IMPL_NONDOC).stdout.split()
        okg = gate["decision"] == "GO" and gate["package_version"] == version and not gd
        R["local_gate_go_on_implementation"] = (PASS, f"full local gate (incl. Python matrix) GO on {gate['source_commit'][:7]}; no non-documentation difference to HEAD") if okg \
            else (FAIL, f"gate decision={gate['decision']} version={gate['package_version']} differing files={gd[:4]}")
    tags = sh("git", "tag", "--list", f"v{version}").stdout.strip()
    R["release_published_and_verified"] = (FAIL, f"no v{version} tag, release or verified artifacts exist") if not tags else (UNVERIFIED, "tag exists; release verification record missing")
    sub = (ROOT / "docs" / "ANTHROPIC_TECHNICAL_SUBMISSION.md").read_text() if (ROOT / "docs" / "ANTHROPIC_TECHNICAL_SUBMISSION.md").exists() else ""
    need = ["IMPLEMENTATION_SHA", "RELEASE_CANDIDATE_SHA", "Scion", "trust policy", "Known unsupported", "Questions for Anthropic", "Reproduce", "Evidence index"]
    miss = [n for n in need if n.lower() not in sub.lower()]
    forbid = re.findall(r"(?i)\b(endorsed by anthropic|anthropic (has )?(reviewed|approved|validated|endorsed)|partnership with anthropic)\b", sub)
    R["submission_doc_complete"] = (PASS, "required sections present; no endorsement claim") if not miss and not forbid else (FAIL, f"missing {miss}; forbidden phrases {forbid}")
    R["submission_doc_names_commits"] = (PASS, f"names IMPLEMENTATION_SHA {impl[:7]}") if impl[:7] in sub else (FAIL, f"does not name IMPLEMENTATION_SHA {impl[:7]}")


def load_critical() -> list[str]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("launch_check", ROOT / "scripts" / "launch_check.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules["launch_check"] = m
    spec.loader.exec_module(m)
    return list(m.CRITICAL_SRC)


def summarize_gate(src: str, out: str) -> None:
    g = json.loads(Path(src).read_text())
    summary = {"source_commit": g["source_commit"], "package_version": g.get("package", {}).get("version") if isinstance(g.get("package"), dict) else g.get("version"),
               "decision": g["decision"], "blocking": g.get("blocking"), "test_counts": g.get("test_counts"), "environment": {k: g.get("environment", {}).get(k) for k in ("python", "platform")},
               "gates": {k: v.get("status") for k, v in g["gates"].items()}, "note": "summary of scripts/release_check.sh run on source_commit (full Python 3.11-3.14 sdist matrix included)"}
    Path(out).write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")


def packaging() -> tuple[str, str]:
    with tempfile.TemporaryDirectory() as d:
        dist = Path(d) / "dist"
        b = sh(sys.executable, "-m", "build", "--wheel", "--outdir", str(dist))
        if b.returncode != 0:
            return FAIL, "build failed: " + b.stderr.strip()[-200:]
        wheel = next(dist.glob("*.whl"))
        v = Path(d) / "v"
        sh(sys.executable, "-m", "venv", str(v))
        inst = sh(str(v / "bin" / "pip"), "install", "-q", f"{wheel}[mcp,a2a]")
        if inst.returncode != 0:
            return UNVERIFIED, "could not install the built wheel here (network or index?): " + inst.stderr.strip()[-160:]
        proj = Path(d) / "p"
        proj.mkdir()
        steps = [[str(v / "bin" / "vep"), "version", "--json"], [str(v / "bin" / "vep"), "init", "--json"], [str(v / "bin" / "vep"), "claude", "install", "--dry-run"],
                 [str(v / "bin" / "python"), "-c", "import vep.mcp_server, vep.a2a_server"], [str(v / "bin" / "vep-mcp"), "--transport", "http"]]
        for i, s in enumerate(steps):
            r = sh(*s, cwd=proj)
            want = 2 if i == 4 else 0
            if r.returncode != want:
                return FAIL, f"{' '.join(s[-3:])} exited {r.returncode}: {r.stderr.strip()[-120:]}"
        asset = sh(str(v / "bin" / "python"), "-c", "from importlib import resources; print(len(list((resources.files('vep')/'assets'/'claude'/'skill').iterdir())))", cwd=proj)
        if asset.stdout.strip() == "0" or asset.returncode != 0:
            return FAIL, "package data (skill assets) missing from the wheel"
        return PASS, f"{wheel.name} built, installed in a fresh venv, CLI/MCP/A2A entry points and skill assets present"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true", help="run the full test suite now (about 2 minutes)")
    ap.add_argument("--junit", help="JUnit XML of an existing run")
    ap.add_argument("--run-packaging", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--evaluated-commit", help="the pushed commit whose hosted checks are evaluated (default HEAD); HEAD may differ only by documentation")
    ap.add_argument("--branch", default="protocol/claude-native-0.6")
    ap.add_argument("--decision-out", help="write the machine-readable GO/NO_GO decision here")
    ap.add_argument("--summarize-gate", nargs=2, metavar=("RELEASE_GATE_JSON", "OUT"))
    a = ap.parse_args()
    if a.summarize_gate:
        summarize_gate(*a.summarize_gate)
        return 0
    junit_path = Path(a.junit) if a.junit else None
    if a.run:
        junit_path = Path(tempfile.mkdtemp()) / "junit.xml"
        sh(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit_path}", timeout=1800)
    results = collect(Junit(junit_path), a.run_packaging, a.evaluated_commit, a.branch)
    import hashlib
    head = git_head()
    evaluated = a.evaluated_commit or head
    profiles = evaluate_profiles(results)
    impl = sh("git", "log", "-1", "--format=%H", evaluated, "--", *IMPL_NONDOC).stdout.strip()
    runs = sh("gh", "run", "list", "--commit", evaluated, "--json", "workflowName,conclusion,url")
    ev_files = ["docs/evidence/installed-wheel-e2e.json", "docs/evidence/release-gate-summary.json", "docs/dogfood/vep-on-vep-run-6-0.6-candidate.json",
                "docs/external/pyflakes-0.6-candidate.json", "docs/external/more-itertools-0.6-candidate.json", "conformance/vectors/suite-1.2.json"]
    doc = {"provenance": {
               "IMPLEMENTATION_SHA": impl, "evaluated_commit": evaluated, "RELEASE_CANDIDATE_SHA_at_computation": head,
               "files_differing_between_evaluated_and_head": sh("git", "diff", "--name-only", evaluated, head).stdout.split(),
               "tree_dirty": bool(sh("git", "status", "--porcelain", "--untracked-files=no").stdout.strip()),
               "producing_hosted_runs": json.loads(runs.stdout) if runs.returncode == 0 and runs.stdout.strip() else [],
               "environment": {"python": sys.version.split()[0], "platform": sys.platform, "command": "python scripts/profile_check.py --run --run-packaging --evaluated-commit <sha>"},
               "evidence_sha256": {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in ev_files if (ROOT / f).exists()},
               "published_artifact_digest": None, "note": "profiles are computed for the evaluated commit; HEAD may add documentation and evidence files only (checked by implementation_frozen)"},
           "source_commit": evaluated, "profiles": profiles,
           "note": "a gate is YES only when all of its own prerequisites pass; composite gates list their component profiles explicitly; there is no umbrella claim that exceeds its weakest mandatory component"}
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    if a.out:
        Path(a.out).write_text(text)
    if a.decision_out:
        rc = profiles["RELEASE_CANDIDATE_READY"]
        decision = {"decision": "GO" if rc["ready"] == "YES" else "NO_GO", "scope": "release candidate 0.6.0b1 (merge, tag and publication are separate, unauthorized steps)",
                    "IMPLEMENTATION_SHA": impl, "evaluated_commit": evaluated, "blocking": rc["blocking"],
                    "gates": {k: v["ready"] for k, v in profiles.items()},
                    "unverified_or_open": {k: list(v["blocking"]) for k, v in profiles.items() if v["blocking"] and k != "RELEASE_CANDIDATE_READY"}}
        Path(a.decision_out).write_text(json.dumps(decision, indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: v["ready"] for k, v in profiles.items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
