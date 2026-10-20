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

PROFILES: dict[str, list[str]] = {
    "CORE_PROTOCOL_CONFORMANT": ["spec_present", "suites_regenerate", "python_vectors", "node_vectors", "reason_code_coverage"],
    "CORE_PROTOCOL_PRODUCTION_READY": ["spec_present", "suites_regenerate", "python_vectors", "node_vectors", "reason_code_coverage", "tests_trust_anchor",
                                       "tests_reuse_chain", "tests_fault_injection", "tests_adversarial", "tests_compat_migration"],
    "REFERENCE_IMPLEMENTATION_READY": ["full_suite", "tests_fault_injection", "tests_compat_migration", "packaging_install_smoke", "hosted_ci_for_head"],
    "MCP_INTEGRATION_READY": ["tests_mcp_stdio", "tests_agent_sdk_contract", "mcp_remote_http_not_offered"],
    "A2A_INTEGRATION_READY": ["tests_a2a", "tests_lost_response_and_capabilities"],
    "CLAUDE_INTEGRATION_READY": ["tests_claude_installer", "claude_plugin_validate", "claude_client_discovery", "claude_live_tool_use"],
    "ISOLATED_EXECUTION_READY": ["isolation_evidence_current"],
    "UNTRUSTED_EXECUTION_READY": ["external_security_review", "escape_testing"],
    "PUBLIC_ANNOUNCEMENT_READY": ["candidate_version_set", "hosted_ci_for_head", "candidate_release_artifacts_verified", "packaging_install_smoke"],
}
SCOPE = {
    "CORE_PROTOCOL_PRODUCTION_READY": "the Core Profile as specified (verification semantics, trust policy, derived attestations); says nothing about the reference implementation's hosting or hostile code",
    "MCP_INTEGRATION_READY": "local stdio transport only; remote HTTP is not offered",
    "A2A_INTEGRATION_READY": "authenticated JSON-RPC on loopback by default; streaming exercised in tests, push notifications not offered; not qualified for public-internet exposure",
}


def evaluate_profiles(results: dict[str, tuple[str, str]]) -> dict:
    out = {}
    for name, reqs in PROFILES.items():
        got = {r: results.get(r, (UNVERIFIED, "no check implemented")) for r in reqs}
        blocking = {r: f"{s}: {d}" for r, (s, d) in got.items() if s != PASS}
        out[name] = {"ready": "YES" if not blocking else "NO", "prerequisites": {r: {"status": s, "detail": d} for r, (s, d) in got.items()},
                     "blocking": blocking, **({"scope": SCOPE[name]} if name in SCOPE else {})}
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


def collect(junit: Junit, run_packaging: bool) -> dict[str, tuple[str, str]]:
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
    head = git_head()
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
    R["candidate_release_artifacts_verified"] = (FAIL, "no candidate release exists; nothing has been built, tagged or published for it")
    return R


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
    a = ap.parse_args()
    junit_path = Path(a.junit) if a.junit else None
    if a.run:
        junit_path = Path(tempfile.mkdtemp()) / "junit.xml"
        sh(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit_path}", timeout=1800)
    results = collect(Junit(junit_path), a.run_packaging)
    doc = {"source_commit": git_head(), "tree_dirty": bool(sh("git", "status", "--porcelain", "--untracked-files=no").stdout.strip()),
           "profiles": evaluate_profiles(results), "note": "a profile is YES only when all of its own prerequisites PASS; there is no umbrella PRODUCTION_READY"}
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    if a.out:
        Path(a.out).write_text(text)
    print(json.dumps({k: v["ready"] for k, v in doc["profiles"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
