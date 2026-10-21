"""Regression tests for defects found in the 0.4.0a1 security review (see docs/SECURITY_REVIEW.md)."""
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import unittest
from unittest import mock

from vep import budgets, candidates, certificates, execution, isolation, snapshots, tokens
from vep.errors import BudgetError, SchemaError, SnapshotError, VepError, VerificationFailed
from tests.helpers import BASE_FILES, VepTestCase, src_env


class StateDirectoryTests(VepTestCase):
    def test_SR02_state_directory_and_key_are_owner_only(self):
        e = self.env()
        self.assertEqual(stat.S_IMODE(os.stat(e.ws.state).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(e.ws.keys_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(e.keystore.path).st_mode), 0o600)


class MountInjectionTests(unittest.TestCase):
    IMAGE = "python@sha256:" + "a" * 64

    def test_SR03_crafted_paths_cannot_add_docker_mount_options(self):
        for bad in ("/tmp/x,target=/etc", "/tmp/x,readonly=false", "/tmp/a=b", "/tmp/with space", "/tmp/../etc",
                    "relative/path", "/tmp/x\nnewline", "/tmp/x;rm"):
            with self.assertRaises(SchemaError, msg=bad):
                isolation.build_plan(self.IMAGE, bad, ["python"])
        isolation.build_plan(self.IMAGE, "/tmp/ok_dir-1/src", ["python"])

    def test_SR03_extra_mounts_are_validated_too(self):
        with self.assertRaises(SchemaError):
            isolation._plan(self.IMAGE, "/tmp/src", [("/tmp/x,target=/", "/vep/r.py")], ["python"], "n")


class SnapshotRaceTests(VepTestCase):
    def test_SR04_symlink_swapped_in_after_scan_is_not_followed(self):
        e = self.env()
        outside = self.tmp / "outside-secret.txt"; outside.write_text("SECRET")
        link = self.tmp / "swap"; os.symlink(outside, link)
        with self.assertRaises(SnapshotError):
            snapshots.read_regular_nofollow(str(link))
        self.assertEqual(snapshots.read_regular_nofollow(str(e.root / "arithmetic.py")), BASE_FILES["arithmetic.py"].encode())

    def test_SR04_race_between_scan_and_read_is_rejected(self):
        e = self.env()
        outside = self.tmp / "outside-secret.txt"; outside.write_text("SECRET")
        real = snapshots.scan_tree

        def scan_then_swap(root, excludes=snapshots.DEFAULT_EXCLUDES):
            found = real(root, excludes)
            target = e.root / "arithmetic.py"
            target.unlink(); os.symlink(outside, target)  # attacker wins the race
            return found
        with mock.patch.object(snapshots, "scan_tree", scan_then_swap):
            with self.assertRaises(SnapshotError):
                snapshots.take_snapshot(e.ws)
        self.assertFalse(any(b"SECRET" in p.read_bytes() for p in (e.ws.state / "cas").rglob("*") if p.is_file()))


class BudgetRangeTests(VepTestCase):
    def test_SR05_overflow_and_negative_amounts_are_rejected_cleanly(self):
        e = self.env(budget=None)
        budgets.create_account(e.ws, "a", "objective", "1")
        for bad in ("9999999999999999999999", "5000000000000000", "-0.000001", "-5"):
            with self.assertRaises(BudgetError, msg=bad):
                budgets.reserve(e.ws, "a", bad, "k-" + bad)
        with self.assertRaises(BudgetError):
            budgets.create_account(e.ws, "huge", "objective", "99999999999999999999999")
        self.assertEqual(budgets.available(e.ws, "a"), 1)

    def test_SR05_cli_never_prints_a_traceback_for_overflow(self):
        e = self.env(budget=None)
        r = subprocess.run([sys.executable, "-m", "vep", "budget", "create", "--account", "x", "--kind", "objective",
                            "--limit", "99999999999999999999999", "--root", str(e.root)], capture_output=True, text=True, env=src_env())
        self.assertEqual(r.returncode, 5)
        self.assertNotIn("Traceback", r.stderr)

    def test_partial_failure_in_receipt_settlement_rolls_back_everything(self):
        e = self.env(budget=None)
        cid = e.candidate()
        rec = tokens.make_receipt(provider="p", model="m", pricing_version="v", candidate_id=cid, attempt=0,
                                  ordinary_input_tokens=1, cached_input_tokens=0, cache_write_tokens=0, output_tokens=1,
                                  reasoning_tokens_in_output=0, prices_per_million={"input": "1", "cached_input": "1",
                                  "cache_write": "1", "output": "1"}, usage_source="simulated", idempotency_key="k")
        with self.assertRaises(BudgetError):
            tokens.record_receipt(e.ws, rec, reservation_key="no-such-reservation")
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM token_receipts").fetchone()[0], 0)


class EvaluationBypassTests(VepTestCase):
    def test_SR06_package_init_load_tests_cannot_replace_the_required_suite(self):
        """An added tests/__init__.py defining load_tests must not be able to substitute a trivial suite."""
        e = self.env()
        evil = ("import unittest\n\ndef load_tests(loader, standard_tests, pattern):\n"
                "    class Trivial(unittest.TestCase):\n        def test_ok(self):\n            pass\n"
                "    return unittest.TestSuite([Trivial('test_ok')])\n")
        r = e.evaluate(e.candidate({"tests/__init__.py": evil}))
        if r["status"] == "REJECTED":
            self.assertTrue(any(k in r["reason"] for k in ("REQUIRED_SUITE", "TOO_FEW", "ZERO")), r)
        else:  # the required tests demonstrably ran (2 passed), so nothing was substituted
            self.assertEqual((r["verdict"], r["counts"]["passed"]), ("PASS", 2))

    def test_SR06_substituting_the_required_module_itself_is_blocked_by_its_digest(self):
        e = self.env()
        evil = ("import unittest\n\ndef load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n")
        cid = e.candidate({"tests/test_arithmetic.py": evil})
        self.assertTrue(any("REQUIRED_TEST_MODIFIED" in v for v in candidates.check_policy(e.ws, cid)))

    def test_evidence_cannot_be_replayed_onto_another_candidate(self):
        e = self.env()
        a = e.candidate({"a.py": "A=1\n"}); b = e.candidate({"b.py": "B=1\n"})
        e.evaluate(a)
        candidates.check_policy(e.ws, b)
        with e.ws.db.read() as c:
            row = dict(c.execute("SELECT * FROM evidence WHERE candidate_id=?", (a,)).fetchone())
        v = candidates.get_state(e.ws, b)["version"]
        for to in ("BUDGET_RESERVED", "EVALUATING"):
            v = candidates.transition(e.ws, b, to, v, "t", "r")
        with e.ws.db.tx() as c:  # attacker with DB access copies A's evidence row under B's name
            c.execute("INSERT INTO evidence(id,candidate_id,objective_id,snapshot_id,policy_id,action_id,verdict,envelope_digest,trust_level)"
                      " VALUES(?,?,?,?,?,?,?,?,?)", ("evd-" + "0" * 64, b, row["objective_id"], row["snapshot_id"], row["policy_id"],
                      row["action_id"], "PASS", row["envelope_digest"], row["trust_level"]))
            sb = c.execute("SELECT snapshot_id FROM candidates WHERE id=?", (b,)).fetchone()[0]
        # the replayed row does not match B's snapshot, so even the storage guard refuses EVIDENCE_READY
        with self.assertRaises(Exception):
            candidates.transition(e.ws, b, "EVIDENCE_READY", v, "t", "replay", "evd-" + "0" * 64)
        self.assertNotEqual(row["snapshot_id"], sb)

    def test_deleted_file_changes_snapshot_identity_and_invalidates_certificate(self):
        e = self.env()
        cid = e.candidate({"extra.py": "X=1\n", "gone.py": "Y=1\n"}); e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        (e.last_dir / "gone.py").unlink()
        with self.assertRaisesRegex(VerificationFailed, "SOURCE_CHANGED"):
            certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)

    def test_exec_bit_change_invalidates_certificate(self):
        e = self.env()
        cid = e.candidate({"extra.py": "X=1\n"}); e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        os.chmod(e.last_dir / "extra.py", 0o755)
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)

    def test_R020_missing_optional_pytest_fails_clearly_before_executing(self):
        e = self.env(evaluator={"kind": "pytest", "targets": ["tests"], "import_roots": ["."], "min_tests": 1})
        cid = e.candidate()
        with mock.patch("importlib.util.find_spec", return_value=None), \
                mock.patch.object(execution, "_run_limited", side_effect=AssertionError("must not run")):
            with self.assertRaisesRegex(VepError, "optional dependency 'pytest'"):
                e.evaluate(cid)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")


class OfflineTests(VepTestCase):
    def test_R019_complete_lifecycle_works_with_networking_disabled(self):
        def no_net(*a, **k):
            raise AssertionError("network access attempted")
        with mock.patch.object(socket.socket, "connect", no_net), mock.patch("socket.create_connection", no_net), \
                mock.patch("socket.getaddrinfo", no_net):
            e = self.env()
            cid = e.candidate({"x.py": "A=1\n"})
            e.evaluate(cid)
            cert = certificates.certify(e.ws, cid)
            self.assertTrue(certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir))
            from vep import cache_planner, routing, simulation
            simulation.run_strategies(simulation.SimParams(n_tasks=50))
            cache_planner.plan(cache_planner.CacheInputs.build(prefix_tokens=1, suffix_tokens=0, output_tokens=0,
                ordinary_input_price="1", cache_write_multiplier="1.25", cache_read_multiplier="0.1", expected_reuses=3))


if __name__ == "__main__":
    unittest.main()


class StaticGuardTests(unittest.TestCase):
    """Whole classes of errors removed by construction: no shell strings, no dynamic eval, no unsafe deserializers."""
    FORBIDDEN = ("shell=True", "os.system(", "os.popen(", "eval(", "exec(", "pickle", "marshal", "yaml.load", "__import__(",
                 "subprocess.getoutput", "input(")

    def source_files(self):
        root = os.path.join(os.path.dirname(__file__), "..", "src", "vep")
        return [os.path.join(root, f) for f in sorted(os.listdir(root)) if f.endswith(".py")]

    def test_src_uses_no_dangerous_primitives(self):
        offenders = []
        for path in self.source_files():
            for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                if any(tok in code for tok in self.FORBIDDEN):
                    offenders.append(f"{os.path.basename(path)}:{n}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_every_subprocess_call_uses_an_argument_list(self):
        import ast
        for path in self.source_files():
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "check_output", "call") \
                        and getattr(node.func.value, "id", "") == "subprocess":
                    first = node.args[0] if node.args else None
                    where = f"{os.path.basename(path)}:{node.lineno}"
                    self.assertIsNotNone(first, where)
                    self.assertNotIsInstance(first, (ast.Constant, ast.JoinedStr), f"{where}: command given as a string")
                    if isinstance(first, ast.BinOp):  # list concatenation is fine, '%'-formatting a string is not
                        self.assertNotIsInstance(first.op, ast.Mod, where)
