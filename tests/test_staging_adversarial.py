"""Adversarial tests that exercise the OPTIMIZED paths (flags on): mutation of the CAS at the worst moment, partial writes, unsupported clone, permissions under unusual
umasks, and equivalence of rejection semantics with the plain path. A performance gain that weakens any of these is rejected."""
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import AUTH, Env, VepTestCase
from tests.test_staging_equivalence import COMBOS, FILES, tree_facts
from vep import candidates, controller, execution, snapshots
from vep.snapshots import BlobScope

OPT = "staging_fast,staging_clone,verified_handoff"


class OptimizedPathAdversarial(VepTestCase):
    def setUp(self):
        super().setUp()
        self.old = os.environ.get("VEP_PERF")
        self.addCleanup(lambda: os.environ.pop("VEP_PERF", None) if self.old is None else os.environ.__setitem__("VEP_PERF", self.old))

    def fresh(self):
        return Env(Path(tempfile.mkdtemp(dir=self.tmp)), files={**FILES})

    def run_candidate(self, e, files):
        cid = e.candidate(files)
        controller.enqueue(e.ws, cid)
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        return cid, out

    def certified_count(self, e):
        with e.ws.db.read() as c:
            return c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"]

    def test_cas_blob_corrupted_after_the_verifying_read_is_never_certified_wrongly(self):
        """The worst moment: the blob changes on disk after the verifying pass and before staging. Plain path: the staging read fails. Handoff: the staged bytes are the
        verified ones. Clone: the staged bytes are the corrupted ones and the pre-run tree hash must reject them. In no variant may a tree that differs from the snapshot be certified."""
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            e = self.fresh()
            cid = e.candidate({"extra.py": "Y = 2\n"})
            snap = e.ws.get_object(candidates.get_state(e.ws, cid)["snapshot_id"], "Snapshot")
            digest = next(x["digest"] for x in snap["entries"] if x["path"] == "extra.py")
            real_mat = snapshots.materialize

            def corrupt_then_stage(ws, s, dest, readonly=True, scope=None, _d=digest):
                p = ws.cas._path(_d); os.chmod(p, 0o644); p.write_bytes(b"Y = 999\n")  # same size, different bytes
                return real_mat(ws, s, dest, readonly, scope)
            with mock.patch.object(execution, "materialize", corrupt_then_stage):
                controller.enqueue(e.ws, cid)
                out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
            if out.get("candidate_status") == "CERTIFIED":  # allowed only if the certified snapshot's blob is the ORIGINAL bytes (handoff staged the verified bytes)
                self.assertIn("handoff", combo or "x", combo)
                staged_ok = out.get("verdict") == "PASS"
                self.assertTrue(staged_ok)
            else:
                self.assertEqual(self.certified_count(e), 0, combo)

    def test_concurrent_cas_tampering_during_staging_never_yields_a_wrong_certificate(self):
        os.environ["VEP_PERF"] = OPT
        e = self.fresh()
        cid = e.candidate({"extra.py": "Y = 2\n", "more.py": "Z = 3\n"})
        snap = e.ws.get_object(candidates.get_state(e.ws, cid)["snapshot_id"], "Snapshot")
        digests = [x["digest"] for x in snap["entries"] if x["path"] in ("extra.py", "more.py")]
        stop = threading.Event()

        def flip():
            while not stop.is_set():
                for d in digests:
                    p = e.ws.cas._path(d)
                    try:
                        os.chmod(p, 0o644); p.write_bytes(b"#" * 6)
                    except OSError:
                        pass
        t = threading.Thread(target=flip, daemon=True); t.start()
        try:
            controller.enqueue(e.ws, cid)
            out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        finally:
            stop.set(); t.join(5)
        if out.get("candidate_status") == "CERTIFIED":
            from vep import certificates
            certificates.verify_certificate(e.ws, out["certificate_id"])  # whatever was certified must still verify against its own snapshot

    def test_source_mutated_by_the_tests_is_detected_in_every_variant(self):
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            e = self.fresh()
            mut = {"tests/test_mutate.py": "import unittest, pathlib\n\n\nclass T(unittest.TestCase):\n    def test_m(self):\n        p = pathlib.Path(__file__).parent.parent / 'a.py'\n"
                                           "        import os; os.chmod(p, 0o644); p.write_text('X = 2\\n')\n"}
            cid, out = self.run_candidate(e, mut)
            self.assertNotEqual(out.get("candidate_status"), "CERTIFIED", combo)

    def test_partial_write_failure_rejects_and_certifies_nothing(self):
        for combo in ("staging_fast", "staging_fast,verified_handoff"):
            os.environ["VEP_PERF"] = combo
            e = self.fresh()
            cid = e.candidate({"extra.py": "Y = 2\n"})
            real = os.write
            calls = {"n": 0}

            def failing(fd, data):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise OSError(28, "No space left on device")
                return real(fd, data)
            controller.enqueue(e.ws, cid)
            with mock.patch.object(snapshots.os, "write", failing):
                out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
            self.assertNotEqual(out.get("candidate_status"), "CERTIFIED", combo)
            self.assertEqual(self.certified_count(e), 0)

    @unittest.skipUnless(sys.platform == "darwin", "clonefile is macOS-only; elsewhere the clone flag falls back by design")
    def test_unsupported_clone_falls_back_to_a_normal_write(self):
        os.environ["VEP_PERF"] = "staging_fast,staging_clone"
        e = self.fresh()
        snap = snapshots.take_snapshot(e.ws)
        d = Path(tempfile.mkdtemp(dir=self.tmp)) / "s"
        with mock.patch.object(snapshots, "_clonefile", lambda: (lambda *a: -1)):  # the filesystem refuses every clone
            snapshots.materialize(e.ws, snap, d)
        self.addCleanup(snapshots.make_writable, d)
        os.environ["VEP_PERF"] = "none"
        ref = Path(tempfile.mkdtemp(dir=self.tmp)) / "s"
        snapshots.materialize(e.ws, snap, ref)
        self.addCleanup(snapshots.make_writable, ref)
        self.assertEqual(tree_facts(d), tree_facts(ref))

    def test_modes_are_identical_under_unusual_umasks(self):
        e = self.fresh()
        snap = snapshots.take_snapshot(e.ws)
        old = os.umask(0o077)
        try:
            os.environ["VEP_PERF"] = "none"
            ref = Path(tempfile.mkdtemp(dir=self.tmp)) / "s"; snapshots.materialize(e.ws, snap, ref)
            os.environ["VEP_PERF"] = OPT
            fast = Path(tempfile.mkdtemp(dir=self.tmp)) / "s"; snapshots.materialize(e.ws, snap, fast)
            os.umask(0o000)
            fast2 = Path(tempfile.mkdtemp(dir=self.tmp)) / "s"; snapshots.materialize(e.ws, snap, fast2)
        finally:
            os.umask(old)
        for d in (ref, fast, fast2):
            self.addCleanup(snapshots.make_writable, d)
        self.assertEqual(tree_facts(fast), tree_facts(ref)); self.assertEqual(tree_facts(fast2), tree_facts(ref))
        for p in fast.rglob("*"):
            m = stat.S_IMODE(os.lstat(p).st_mode)
            self.assertEqual(m & 0o222, 0, p)  # nothing writable, files and directories

    def test_rejection_semantics_match_the_plain_path_for_a_failing_candidate(self):
        results = {}
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            e = self.fresh()
            cid, out = self.run_candidate(e, {"a.py": "X = (\n"})
            results[combo] = (out.get("candidate_status"), out.get("verdict"))
        self.assertEqual(len(set(results.values())), 1, results)


if __name__ == "__main__":
    unittest.main()
