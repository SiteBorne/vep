"""Release-engineering regression tests: gates, claims, secrets, artifacts, workflows (R008-R011, R017, R021-R024)."""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


G = load("release_gates", "scripts/release/gates.py")
POLICY = G.load_policy()
OK = {"status": "PASS", "detail": ""}


def gates(**over):
    d = {g: dict(OK) for g in POLICY["required_gates"]}
    d.update({"OPTIONAL_ISOLATION": {"status": "UNVERIFIED", "detail": ""}})
    for k, v in over.items():
        d[k] = {"status": v, "detail": ""}
    return d


class DecisionTests(unittest.TestCase):
    def test_R021_go_only_when_every_required_gate_passes(self):
        d = G.decide(gates(), POLICY)
        self.assertEqual(d["decision"], "GO")
        self.assertEqual(d["capabilities"]["PUBLIC_DEVELOPER_PREVIEW"], "PASS")
        self.assertEqual(d["capabilities"]["UNTRUSTED_EXECUTION_ISOLATION"], "UNVERIFIED")

    def test_R021_any_required_non_pass_status_is_no_go(self):
        for bad in ("FAIL", "NOT_RUN", "UNVERIFIED", "NOT_APPLICABLE", "GREEN"):
            for gate in POLICY["required_gates"]:
                d = G.decide(gates(**{gate: bad}), POLICY)
                self.assertEqual(d["decision"], "NO_GO", (gate, bad))
                self.assertEqual(d["capabilities"]["PUBLIC_DEVELOPER_PREVIEW"], "FAIL")

    def test_R021_missing_required_gate_is_no_go(self):
        g = gates(); del g["SECRET_SCAN"]
        self.assertEqual(G.decide(g, POLICY)["decision"], "NO_GO")

    def test_optional_gates_cannot_rescue_or_block_the_preview(self):
        self.assertEqual(G.decide(gates(OPTIONAL_ISOLATION="FAIL"), POLICY)["decision"], "GO")
        d = G.decide(gates(SECRET_SCAN="FAIL", OPTIONAL_ISOLATION="PASS"), POLICY)
        self.assertEqual(d["decision"], "NO_GO")

    def test_isolation_capability_is_only_pass_when_observed_pass(self):
        d = G.decide(gates(OPTIONAL_ISOLATION="PASS"), POLICY)
        self.assertEqual(d["capabilities"]["UNTRUSTED_EXECUTION_ISOLATION"], "PASS")
        for st in ("NOT_RUN", "UNVERIFIED", "NOT_APPLICABLE", "FAIL"):
            self.assertNotEqual(G.decide(gates(OPTIONAL_ISOLATION=st), POLICY)["capabilities"]["UNTRUSTED_EXECUTION_ISOLATION"], "PASS")

    def test_R021_release_gate_main_exits_nonzero_when_a_gate_fails(self):
        rg = load("release_gate_main", "scripts/release/release_gate.py")
        passing = lambda c: G.gate("PASS", "stub")
        failing = lambda c: G.gate("FAIL", "stub failure")
        names = {n for n, _ in rg.ORDER}
        rg.ORDER[:] = [(n, failing if n == "SECRET_SCAN" else passing) for n, _ in rg.ORDER]
        rg.g_pycompat = lambda c, skip=False: G.gate("PASS", "stub")
        rg.sys.argv = ["release_gate.py", "--no-write"]
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rg.main(), 1)
        self.assertIn("SECRET_SCAN", names)


class ClaimPolicyTests(unittest.TestCase):
    CAPS = {"UNTRUSTED_EXECUTION_ISOLATION": "UNVERIFIED"}

    def scan(self, text, caps=None):
        return G.scan_claims(text, POLICY, caps or self.CAPS, "x.md")

    def test_R024_unsupported_security_claims_are_rejected(self):
        for line in ("VEP can safely run untrusted code.", "It is production-ready.", "Achieves SLSA level 3.",
                     "Candidates run in a fully isolated sandbox.", "This guarantees correctness.", "The globally optimal policy."):
            self.assertTrue(self.scan(line), line)

    def test_negated_or_limiting_statements_are_allowed(self):
        for line in ("VEP is not production-ready.", "Never run untrusted code with the local evaluator.",
                     "It cannot safely run untrusted code.", "No SLSA level is claimed (SLSA level 3 would require more).",
                     "Isolation is unverified."):
            self.assertEqual(self.scan(line), [], line)

    def test_isolation_claims_need_the_verified_capability(self):
        line = "Candidates run in a fully isolated sandbox."
        self.assertTrue(self.scan(line))
        self.assertEqual(self.scan(line, {"UNTRUSTED_EXECUTION_ISOLATION": "PASS"}), [])
        self.assertTrue(self.scan("It is production-ready.", {"UNTRUSTED_EXECUTION_ISOLATION": "PASS"}))

    def test_shipped_documentation_makes_no_unsupported_claims(self):
        hits = []
        for pat in POLICY["claim_scan_paths"]:
            for f in sorted(ROOT.glob(pat)):
                hits += G.scan_claims(f.read_text(), POLICY, self.CAPS, f.name)
        self.assertEqual(hits, [])


class SecretScanTests(unittest.TestCase):
    def test_patterns_detect_without_echoing_values(self):
        samples = ["-----BEGIN " + "PRIVATE KEY-----", "AKIA" + "ABCDEFGHIJKLMNOP", "ghp_" + "a" * 36,
                   "pypi-AgEI" + "x" * 30, 'api_key = "' + "A1b2C3d4" * 3 + '"', "sk-ant-" + "q" * 40]
        for s in samples:
            hits = G.scan_text_for_secrets(f"line1\n{s}\n", POLICY, "f")
            self.assertEqual(len(hits) >= 1 and hits[0]["line"], 2, s)
            self.assertNotIn(s, json.dumps(hits))

    def test_history_scan_finds_secrets_deleted_from_the_current_tree(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d, True)
        run = lambda *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e.x", *a], cwd=d, check=True, capture_output=True)
        run("init", "-q", "-b", "main")
        (d / "config.txt").write_text("token = '" + "Zz9" * 8 + "'\n")
        run("add", "-A"); run("commit", "-q", "-m", "oops")
        (d / "config.txt").unlink()
        run("add", "-A"); run("commit", "-q", "-m", "remove")
        self.assertEqual(G.scan_tree(POLICY, d), [])                # current tree is clean...
        self.assertTrue(G.scan_history(POLICY, d))                  # ...but history is not
        key = d / "signing.pem"; key.write_text("x"); run("add", "-A"); run("commit", "-q", "-m", "k")
        self.assertTrue(any(h["rule"].startswith("FORBIDDEN_FILENAME") for h in G.scan_history(POLICY, d)))

    def test_shipped_repository_tree_has_no_secrets_or_key_files(self):
        self.assertEqual(G.scan_tree(POLICY, ROOT), [])


class ArtifactAuditTests(unittest.TestCase):
    def make_wheel(self, members):
        p = Path(tempfile.mkdtemp()) / "x-1-py3-none-any.whl"
        with zipfile.ZipFile(p, "w") as z:
            for n, data in members.items():
                z.writestr(n, data)
        self.addCleanup(shutil.rmtree, p.parent, True)
        return p

    def test_R008_R009_audit_rejects_keys_databases_env_state_and_machine_paths(self):
        p = self.make_wheel({"vep/ok.py": "x=1\n", "vep/signing.pem": "k", ".vep/keys/a": "k", "vep/data.db": "d",
                             "vep/.env": "A=1", "vep/p.py": "PATH='" + "/Us" + "ers/someone/x'\n"})
        msgs = " | ".join(G.audit_artifact(p, POLICY))
        for needle in ("signing.pem", ".vep", "data.db", ".env", "/Us" + "ers/"):
            self.assertIn(needle, msgs)
        self.assertEqual(G.audit_artifact(self.make_wheel({"vep/ok.py": "x=1\n"}), POLICY), [])

    def test_audit_covers_sdist_and_embedded_secrets(self):
        p = Path(tempfile.mkdtemp()) / "x-1.tar.gz"; self.addCleanup(shutil.rmtree, p.parent, True)
        with tarfile.open(p, "w:gz") as t:
            data = ("AKIA" + "ABCDEFGHIJKLMNOP").encode()
            ti = tarfile.TarInfo("x-1/conf.txt"); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        self.assertTrue(any("secret pattern" in m for m in G.audit_artifact(p, POLICY)))

    def test_checksum_manifest_detects_modification(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d, True)
        a = d / "a.whl"; a.write_bytes(b"one")
        G.write_checksums([a], d / "SHA256SUMS")
        self.assertEqual(G.verify_checksums(d / "SHA256SUMS"), [])
        a.write_bytes(b"two")
        self.assertEqual(G.verify_checksums(d / "SHA256SUMS"), ["a.whl"])
        self.assertEqual(G.verify_checksums(d / "SHA256SUMS")[0], "a.whl")


class RealBuildTests(unittest.TestCase):
    """Builds the real project from tracked+untracked sources in a temp copy (never plants files in the repo)."""
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="vep-build-"))
        src = cls.tmp / "src_copy"
        for f in G.list_files(ROOT):
            if (ROOT / f).is_file():
                (src / f).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / f, src / f)
        (src / "src" / "vep" / "signing.pem").write_text("leak")      # planted: must not reach the artifacts
        (src / ".vep" / "keys").mkdir(parents=True); (src / ".vep" / "keys" / "k").write_text("leak")
        (src / "workspace.db").write_text("leak")
        r = subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(cls.tmp / "out")], cwd=src,
                           capture_output=True, text=True)
        cls.build = r
        cls.out = cls.tmp / "out"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_build_succeeds(self):
        self.assertEqual(self.build.returncode, 0, self.build.stderr[-800:])

    def test_R008_R009_real_artifacts_exclude_keys_and_databases_even_when_planted_in_the_tree(self):
        for f in list(self.out.glob("*.whl")) + list(self.out.glob("*.tar.gz")):
            names = [n for n, _ in G.iter_artifact_members(f)]
            self.assertFalse([n for n in names if n.endswith((".pem", ".db")) or "/.vep/" in n or n.startswith(".vep/")], (f.name, names))
            self.assertEqual(G.audit_artifact(f, POLICY), [], f.name)

    def test_R017_version_metadata_agrees_across_artifacts_and_source(self):
        sys.path.insert(0, str(ROOT / "src"))
        import vep
        from vep import versions
        v = G.version_consistency()
        self.assertEqual(len(set(v.values())), 1, v)
        self.assertEqual(v["pyproject"], vep.__version__)
        self.assertEqual(v["pyproject"], versions.PACKAGE_VERSION)
        whl = next(self.out.glob("*.whl")); sd = next(self.out.glob("*.tar.gz"))
        with zipfile.ZipFile(whl) as z:
            meta = z.read(next(n for n in z.namelist() if n.endswith("METADATA"))).decode()
        self.assertIn(f"Version: {v['pyproject']}", meta)
        self.assertIn(f"-{v['pyproject']}-", whl.name)
        self.assertTrue(sd.name.endswith(f"{v['pyproject']}.tar.gz"))


class WorkflowLintTests(unittest.TestCase):
    GOOD = "name: x\non: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + " # v1\n"

    def test_good_workflow_passes(self):
        self.assertEqual(G.lint_workflow(self.GOOD, POLICY, "g.yml"), [])

    def test_unpinned_actions_missing_permissions_and_pull_request_target_are_rejected(self):
        self.assertTrue(G.lint_workflow(self.GOOD.replace("a" * 40, "v4"), POLICY))
        self.assertTrue(G.lint_workflow(self.GOOD.replace("permissions:\n  contents: read\n", ""), POLICY))
        self.assertTrue(G.lint_workflow(self.GOOD.replace("on: push", "on:\n  pull_request_target:\n    branches: [main]"), POLICY))
        self.assertTrue(G.lint_workflow(self.GOOD.replace("contents: read", "write-all").replace("permissions:\n  write-all", "permissions: write-all"), POLICY))

    def test_shipped_workflows_pass_static_policy(self):
        wfs = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertGreaterEqual(len(wfs), 2)
        for wf in wfs:
            self.assertEqual(G.lint_workflow(wf.read_text(), POLICY, wf.name), [], wf.name)

    def test_publish_job_is_separate_from_pull_request_execution(self):
        rel = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        self.assertNotIn("pull_request", rel)
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertNotIn("id-token: write", ci)
        self.assertNotIn("secrets.", ci)


class SecurityFindingsTests(unittest.TestCase):
    TABLE = ("| SR-01 | HIGH | pre | comp | cause | fix | `tests/test_hardening.py::StateDirectoryTests.test_SR02_state_directory_and_key_are_owner_only` | none | FIXED |\n")

    def test_parser_and_checker(self):
        rows = G.parse_security_findings(self.TABLE)
        self.assertEqual(G.check_security_findings(rows, ROOT), [])
        bad = G.parse_security_findings(self.TABLE.replace("FIXED", "OPEN"))
        self.assertTrue(G.check_security_findings(bad, ROOT))
        ghost = G.parse_security_findings(self.TABLE.replace("test_SR02_state_directory_and_key_are_owner_only", "test_nope"))
        self.assertTrue(any("missing test" in p for p in G.check_security_findings(ghost, ROOT)))
        self.assertTrue(G.check_security_findings([], ROOT))

    def test_recorded_findings_are_consistent(self):
        text = (ROOT / "docs" / "SECURITY_REVIEW.md").read_text()
        self.assertEqual(G.check_security_findings(G.parse_security_findings(text), ROOT), [])


class QuickstartTests(unittest.TestCase):
    def test_R023_public_quickstart_commands_execute(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts/release/quickstart_runner.py"), "--bin-dir", str(Path(sys.executable).parent)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["status"], "PASS")
        self.assertGreaterEqual(doc["blocks"], 7)

    def test_a_failing_block_fails_the_runner(self):
        d = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, d, True)
        (d / "q.md").write_text("```bash quickstart\nfalse\n```\n")
        r = subprocess.run([sys.executable, str(ROOT / "scripts/release/quickstart_runner.py"), "--bin-dir", str(Path(sys.executable).parent),
                            "--doc", str(d / "q.md")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)


class PolicyFileTests(unittest.TestCase):
    def test_policy_is_self_consistent(self):
        self.assertEqual(set(POLICY["allowed_statuses"]), {"PASS", "FAIL", "NOT_RUN", "UNVERIFIED", "NOT_APPLICABLE"})
        required = set(POLICY["required_gates"])
        for g in ("SOURCE_INTEGRITY", "UNIT_TESTS", "SECRET_SCAN", "ARTIFACT_INTEGRITY", "PROTOCOL_COMPATIBILITY",
                  "RELEASE_PROVENANCE", "SECURITY_REVIEW", "CLI_SMOKE_TEST", "PACKAGE_INSTALLATION"):
            self.assertIn(g, required)
        self.assertNotIn("OPTIONAL_ISOLATION", required)
        gate_names = {n for n in POLICY["required_gates"] + POLICY["optional_gates"]}
        rg = load("release_gate_names", "scripts/release/release_gate.py")
        self.assertTrue(required <= {n for n, _ in rg.ORDER})


if __name__ == "__main__":
    unittest.main()
