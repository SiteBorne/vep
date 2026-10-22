"""Performance experiments A (secure staging) and B (verified I/O handoff) must be observationally identical to the plain path and must keep every integrity
property: same bytes/modes, distinct inodes (never a link into the CAS), CAS untouched, symlink races refused, corruption detected, bounded memory."""
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from tests.helpers import AUTH, Env, VepTestCase
from vep import candidates, controller, execution, perf, snapshots
from vep.errors import SnapshotError
from vep.snapshots import BlobScope

COMBOS = ["", "staging_fast", "verified_handoff", "staging_fast,verified_handoff", "staging_fast,staging_clone", "staging_fast,staging_clone,verified_handoff"]
FILES = {"a.py": "X = 1\n", "pkg/__init__.py": "", "pkg/deep/mod.py": "def f():\n    return 1\n", "bin/run.sh": "#!/bin/sh\necho hi\n", "tests/test_a.py": "import unittest\n\n\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertTrue(True)\n"}


def tree_facts(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        st = os.lstat(p)
        out[rel] = ("dir" if stat.S_ISDIR(st.st_mode) else "file", stat.S_IMODE(st.st_mode), hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)
    out["."] = ("dir", stat.S_IMODE(os.lstat(root).st_mode), None)
    return out


class Equivalence(VepTestCase):
    def setUp(self):
        super().setUp()
        self.old = os.environ.get("VEP_PERF")
        self.addCleanup(lambda: os.environ.pop("VEP_PERF", None) if self.old is None else os.environ.__setitem__("VEP_PERF", self.old))

    def fresh(self):
        return Env(Path(tempfile.mkdtemp(dir=self.tmp)), files={**FILES})

    def make(self):
        e = self.fresh()
        os.chmod(e.root / "bin/run.sh", 0o755)
        snap = snapshots.take_snapshot(e.ws)
        return e, snap

    def stage(self, e, snap, combo):
        os.environ["VEP_PERF"] = combo or "none"
        d = Path(tempfile.mkdtemp(dir=self.tmp)) / "stage"
        scope = BlobScope()
        snapshots.verify_snapshot(e.ws, snap, scope)
        snapshots.materialize(e.ws, snap, d, scope=scope)
        self.addCleanup(snapshots.make_writable, d)
        return d

    def test_every_variant_stages_exactly_the_same_tree(self):
        e, snap = self.make()
        ref = tree_facts(self.stage(e, snap, ""))
        for combo in COMBOS[1:]:
            self.assertEqual(tree_facts(self.stage(e, snap, combo)), ref, combo)
        self.assertEqual(snapshots.tree_snapshot_id(self.stage(e, snap, "staging_fast,staging_clone,verified_handoff"), excludes=()), snap.id)

    def test_staged_files_are_distinct_inodes_and_the_cas_is_never_modified(self):
        e, snap = self.make()
        before = {d: (hashlib.sha256(e.ws.cas.get(d)).hexdigest(), os.lstat(e.ws.cas._path(d)).st_ino, os.lstat(e.ws.cas._path(d)).st_nlink, stat.S_IMODE(os.lstat(e.ws.cas._path(d)).st_mode))
                  for d in (x["digest"] for x in snap["entries"])}
        for combo in COMBOS:
            d = self.stage(e, snap, combo)
            for ent in snap["entries"]:
                st = os.lstat(d / ent["path"])
                cst = os.lstat(e.ws.cas._path(ent["digest"]))
                self.assertNotEqual((st.st_dev, st.st_ino), (cst.st_dev, cst.st_ino), f"{combo}: staged file shares an inode with the CAS blob")
                self.assertEqual(st.st_nlink, 1, combo)
            self.assertEqual({k: (hashlib.sha256(e.ws.cas.get(k)).hexdigest(), os.lstat(e.ws.cas._path(k)).st_ino, os.lstat(e.ws.cas._path(k)).st_nlink,
                                  stat.S_IMODE(os.lstat(e.ws.cas._path(k)).st_mode)) for k in before}, before, combo)

    def test_writing_to_a_staged_file_never_reaches_the_cas(self):
        e, snap = self.make()
        d = self.stage(e, snap, "staging_fast,staging_clone,verified_handoff")
        target = d / "a.py"
        os.chmod(target, 0o644)  # the evaluated code runs as the same user and may do this
        target.write_text("X = 666\n")
        digest = next(x["digest"] for x in snap["entries"] if x["path"] == "a.py")
        self.assertEqual(e.ws.cas.get(digest), b"X = 1\n")  # verified read of the CAS blob still matches
        self.assertNotEqual(snapshots.tree_snapshot_id(d, excludes=()), snap.id)  # and the post-run tree check would notice

    def test_symlink_in_the_staging_directory_is_not_followed(self):
        e, snap = self.make()
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            d = Path(tempfile.mkdtemp(dir=self.tmp)) / "stage"
            d.mkdir()
            victim = Path(tempfile.mkdtemp(dir=self.tmp)) / "victim.txt"; victim.write_text("keep")
            os.symlink(victim, d / "a.py")
            with self.assertRaises(SnapshotError):  # non-empty staging directory is refused before anything is written
                snapshots.materialize(e.ws, snap, d)
            self.assertEqual(victim.read_text(), "keep", combo)

    def test_corrupted_blob_is_detected_by_every_variant_and_never_certified(self):
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            e = self.fresh()
            cid = e.candidate({"extra.py": "Y = 2\n"})
            snap = e.ws.get_object(candidates.get_state(e.ws, cid)["snapshot_id"], "Snapshot")
            digest = next(x["digest"] for x in snap["entries"] if x["path"] == "extra.py")
            p = e.ws.cas._path(digest); os.chmod(p, 0o644); p.write_bytes(b"Y = 999\n")  # same-size corruption
            controller.enqueue(e.ws, cid)
            out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
            self.assertNotEqual(out.get("candidate_status"), "CERTIFIED", combo)
            with e.ws.db.read() as c:
                self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 0, combo)

    def test_handoff_memory_is_bounded_and_a_tiny_cap_changes_speed_not_correctness(self):
        e, snap = self.make()
        os.environ["VEP_PERF"] = "verified_handoff,staging_fast"
        scope = BlobScope(cap=10)
        snapshots.verify_snapshot(e.ws, snap, scope)
        self.assertLessEqual(scope.bytes, 10)
        d = Path(tempfile.mkdtemp(dir=self.tmp)) / "stage"
        snapshots.materialize(e.ws, snap, d, scope=scope)
        self.addCleanup(snapshots.make_writable, d)
        self.assertEqual(snapshots.tree_snapshot_id(d, excludes=()), snap.id)

    def test_scope_never_skips_verification_of_an_unverified_snapshot(self):
        e, snap = self.make()
        os.environ["VEP_PERF"] = "verified_handoff"
        digest = snap["entries"][0]["digest"]
        p = e.ws.cas._path(digest); os.chmod(p, 0o644); p.write_bytes(b"garbage")
        with self.assertRaises(SnapshotError):
            snapshots.verify_snapshot(e.ws, snap, BlobScope())

    def test_end_to_end_certification_is_identical_in_every_variant(self):
        for combo in COMBOS:
            os.environ["VEP_PERF"] = combo or "none"
            e = self.fresh()
            cid = e.candidate({"extra.py": "Y = 2\n"})
            controller.enqueue(e.ws, cid)
            out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
            self.assertEqual(out["candidate_status"], "CERTIFIED", combo)


if __name__ == "__main__":
    unittest.main()
