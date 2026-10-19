import os
import unittest

from vep import snapshots
from vep.errors import SnapshotError
from vep.workspace import Workspace
from tests.helpers import BASE_FILES, VepTestCase, write_tree


class SnapshotTests(VepTestCase):
    def mk(self, files=None):
        root = self.tmp / "p"
        root.mkdir(exist_ok=True)
        write_tree(root, files or BASE_FILES)
        return root, Workspace.init(root)

    def test_deterministic_and_content_sensitive(self):
        root, ws = self.mk()
        a = snapshots.take_snapshot(ws)
        b = snapshots.take_snapshot(ws)
        self.assertEqual(a.id, b.id)
        (root / "arithmetic.py").write_text("changed\n")
        c = snapshots.take_snapshot(ws)
        self.assertNotEqual(a.id, c.id)
        self.assertEqual(snapshots.diff(a, c)["modified"], ["arithmetic.py"])

    def test_executable_bit_is_identity_relevant(self):
        root, ws = self.mk()
        a = snapshots.take_snapshot(ws)
        os.chmod(root / "arithmetic.py", 0o755)
        b = snapshots.take_snapshot(ws)
        self.assertNotEqual(a.id, b.id)
        self.assertEqual(snapshots.diff(a, b)["mode_changed"], ["arithmetic.py"])

    def test_internal_state_and_credentials_excluded(self):
        root, ws = self.mk()
        for name in (".env", "server.pem", "id_rsa", "x.key"):
            (root / name).write_text("secret")
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "a.pyc").write_bytes(b"\0")
        paths = [e["path"] for e in snapshots.take_snapshot(ws)["entries"]]
        self.assertEqual(paths, sorted(BASE_FILES))
        self.assertFalse(any(p.startswith(".vep") for p in paths))

    def test_symlinks_rejected(self):
        root, ws = self.mk()
        os.symlink("/etc/passwd", root / "link")
        with self.assertRaises(SnapshotError):
            snapshots.take_snapshot(ws)

    def test_symlinked_directory_rejected(self):
        root, ws = self.mk()
        os.symlink("/tmp", root / "dirlink")
        with self.assertRaises(SnapshotError):
            snapshots.take_snapshot(ws)

    def test_path_validation(self):
        for bad in ("../x", "/abs", "a/../b", "a//b", "a\\b", "", "a/./b", "a\x00b", "a\nb"):
            with self.assertRaises(SnapshotError, msg=repr(bad)):
                snapshots.validate_rel_path(bad)
        self.assertEqual(snapshots.validate_rel_path("a/b.py"), "a/b.py")

    def test_case_and_unicode_collisions(self):
        self.assertEqual(snapshots.find_collisions(["A.py", "a.py"]), [("A.py", "a.py")])
        self.assertTrue(snapshots.find_collisions(["café.py", "café.py"]))
        self.assertEqual(snapshots.find_collisions(["a.py", "b.py"]), [])

    def test_materialize_is_exact_and_readonly(self):
        root, ws = self.mk()
        snap = snapshots.take_snapshot(ws)
        dest = self.tmp / "stage"
        snapshots.materialize(ws, snap, dest)
        self.assertEqual(snapshots.tree_snapshot_id(dest, excludes=()), snap.id)
        with self.assertRaises(PermissionError):
            (dest / "new.txt").write_text("x")
        snapshots.make_writable(dest)

    def test_materialize_refuses_nonempty_dir(self):
        root, ws = self.mk()
        snap = snapshots.take_snapshot(ws)
        (self.tmp / "d").mkdir()
        (self.tmp / "d" / "f").write_text("x")
        with self.assertRaises(SnapshotError):
            snapshots.materialize(ws, snap, self.tmp / "d")

    def test_verify_snapshot_detects_missing_blob(self):
        root, ws = self.mk()
        snap = snapshots.take_snapshot(ws)
        digest = snap["entries"][0]["digest"]
        p = ws.cas._path(digest)
        os.chmod(p, 0o644)
        p.write_bytes(b"corrupt")
        with self.assertRaises(SnapshotError):
            snapshots.verify_snapshot(ws, snap)

    def test_unsorted_entries_rejected(self):
        with self.assertRaises(SnapshotError):
            snapshots.make_snapshot_object([
                {"path": "b", "digest": "0" * 64, "type": "file", "executable": False},
                {"path": "a", "digest": "0" * 64, "type": "file", "executable": False}])


if __name__ == "__main__":
    unittest.main()
