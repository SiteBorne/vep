import shutil
import subprocess
import unittest

from vep import git_adapter, snapshots
from vep.errors import VepError
from tests.helpers import BASE_FILES, VepTestCase, write_tree

HAS_GIT = shutil.which("git") is not None


def git(path, *args):
    subprocess.run(["git", "-C", str(path), "-c", "user.email=t@example.com", "-c", "user.name=t",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@unittest.skipUnless(HAS_GIT, "git not installed: NOT RUN")
class GitTests(VepTestCase):
    def test_non_repo(self):
        e = self.env()
        self.assertEqual(git_adapter.inspect(e.root), {"is_repo": False})

    def make_repo(self):
        e = self.env()
        git(e.root, "init", "-q")
        (e.root / ".gitignore").write_text(".vep/\n")
        git(e.root, "add", "-A")
        git(e.root, "commit", "-q", "-m", "init")
        return e

    def test_head_status_and_changes(self):
        e = self.make_repo()
        info = git_adapter.inspect(e.root)
        self.assertTrue(info["is_repo"]); self.assertFalse(info["dirty"]); self.assertEqual(len(info["head"]), 40)
        first = info["head"]
        (e.root / "arithmetic.py").write_text("changed\n")
        (e.root / "new.txt").write_text("n")
        st = {x["path"]: x["code"] for x in git_adapter.status(e.root)}
        self.assertEqual(st, {"arithmetic.py": " M", "new.txt": "??"})
        git(e.root, "add", "-A"); git(e.root, "commit", "-q", "-m", "two")
        self.assertEqual(git_adapter.changed_files(e.root, first), ["arithmetic.py", "new.txt"])

    def test_associate_records_dirty_flag_and_is_read_only(self):
        e = self.make_repo()
        head = git_adapter.head(e.root)
        snap = snapshots.take_snapshot(e.ws)
        self.assertEqual(git_adapter.associate(e.ws, snap.id)["dirty"], False)
        (e.root / "arithmetic.py").write_text("dirty\n")
        self.assertTrue(git_adapter.associate(e.ws, snap.id)["dirty"])
        self.assertEqual(git_adapter.head(e.root), head)  # no commits created
        self.assertEqual(len(git_adapter.status(e.root)), 1)  # working tree untouched

    def test_only_readonly_subcommands_allowed(self):
        e = self.make_repo()
        for sub in ("commit", "push", "merge", "checkout", "reset", "add", "config"):
            with self.assertRaises(VepError):
                git_adapter._git(e.root, sub)

    def test_argument_injection_blocked(self):
        e = self.make_repo()
        for bad in ("--output=/tmp/x", "HEAD; rm -rf /", "$(id)", "-p", "zz"):
            with self.assertRaises(VepError):
                git_adapter.changed_files(e.root, bad)

    def test_associate_requires_a_commit(self):
        e = self.env()
        git(e.root, "init", "-q")
        with self.assertRaises(VepError):
            git_adapter.associate(e.ws, snapshots.take_snapshot(e.ws).id)


if __name__ == "__main__":
    unittest.main()
