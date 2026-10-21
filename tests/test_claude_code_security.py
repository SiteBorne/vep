"""Security regression tests for the Claude Code installer's file handling (PR #2 CodeQL finding and the real risks behind it)."""
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from vep import claude_code as cc

CANARY = "canary" + "-value-not-a-key"


def mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.addCleanup(self._t.cleanup)
        self._old = os.umask(0o000)  # a permissive umask must not weaken anything
        self.addCleanup(os.umask, self._old)

    def seed(self, with_secret=True):
        env = {"API_TOKEN": CANARY} if with_secret else {}
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x", "env": env}}}))
        os.chmod(self.root / ".mcp.json", 0o600)
        (self.root / ".claude").mkdir()
        (self.root / ".claude/settings.json").write_text(json.dumps({"env": {"TOKEN": CANARY}, "permissions": {"allow": ["Bash(ls)"]}}))
        os.chmod(self.root / ".claude/settings.json", 0o600)


class PermissionTests(Base):
    def test_credential_capable_files_are_owner_only_under_a_permissive_umask(self):
        cc.install(self.root)
        for rel in (".mcp.json", ".claude/settings.json", cc.MANIFEST.as_posix()):
            self.assertEqual(mode(self.root / rel) & 0o077, 0, rel)

    def test_existing_private_files_are_never_widened_by_a_rewrite(self):
        self.seed()
        cc.install(self.root)
        self.assertEqual(mode(self.root / ".mcp.json") & 0o077, 0)
        self.assertEqual(mode(self.root / ".claude/settings.json") & 0o077, 0)
        cc.uninstall(self.root)
        self.assertEqual(mode(self.root / ".mcp.json") & 0o077, 0)
        self.assertEqual(mode(self.root / ".claude/settings.json") & 0o077, 0)

    def test_hook_is_executable_by_owner_only(self):
        cc.install(self.root)
        m = mode(self.root / cc.GUARD_REL)
        self.assertTrue(m & stat.S_IXUSR); self.assertEqual(m & 0o077, 0)

    def test_force_replacement_makes_private_backups(self):
        self.seed()
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"vep": {"command": "mine", "env": {"K": CANARY}}}}))
        cc.install(self.root, force=True)
        bdir = self.root / ".claude/vep-backups"
        self.assertEqual(mode(bdir) & 0o077, 0)
        files = [p for p in bdir.rglob("*") if p.is_file()]
        self.assertTrue(files)
        for p in files:
            self.assertEqual(mode(p) & 0o077, 0, p)
        for d in [p for p in bdir.rglob("*") if p.is_dir()]:
            self.assertEqual(mode(d) & 0o077, 0, d)


class ConfidentialityTests(Base):
    def test_reports_and_status_never_contain_existing_secrets(self):
        self.seed()
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"vep": {"command": "mine", "args": ["--token", CANARY], "env": {"K": CANARY}}}}))
        r = cc.install(self.root)  # conflict
        self.assertEqual(r["status"], "CONFLICT"); self.assertNotIn(CANARY, json.dumps(r))
        self.assertNotIn(CANARY, json.dumps(cc.status(self.root)))
        r = cc.install(self.root, force=True)
        self.assertNotIn(CANARY, json.dumps(r))
        self.assertNotIn(CANARY, json.dumps(cc.uninstall(self.root)))

    def test_failed_installation_does_not_leak_secrets_or_leave_temp_files(self):
        self.seed()
        (self.root / "CLAUDE.md").write_text("x")
        with mock.patch.object(cc.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError) as cm:
                cc.install(self.root)
        self.assertNotIn(CANARY, str(cm.exception))
        self.assertEqual([p for p in self.root.rglob("*") if ".vep-tmp" in p.name], [])
        self.assertIn(CANARY, (self.root / ".mcp.json").read_text())  # original intact

    def test_invalid_json_error_does_not_echo_file_contents(self):
        (self.root / ".mcp.json").write_text('{"token": "' + CANARY + '" oops')
        with self.assertRaises(cc.IntegrationConflict) as cm:
            cc.install(self.root)
        self.assertNotIn(CANARY, str(cm.exception))

    def test_install_uninstall_round_trip_preserves_unrelated_settings(self):
        self.seed()
        before_mcp = json.loads((self.root / ".mcp.json").read_text())
        before_set = json.loads((self.root / ".claude/settings.json").read_text())
        cc.install(self.root); cc.uninstall(self.root)
        self.assertEqual(json.loads((self.root / ".mcp.json").read_text()), before_mcp)
        self.assertEqual(json.loads((self.root / ".claude/settings.json").read_text()), before_set)

    def test_authority_and_permissions_are_not_changed_by_install(self):
        self.seed()
        cc.install(self.root)
        st = json.loads((self.root / ".claude/settings.json").read_text())
        self.assertEqual(st["permissions"], {"allow": ["Bash(ls)"]})
        args = json.loads((self.root / ".mcp.json").read_text())["mcpServers"]["vep"]["args"]
        self.assertIn("read,register", args); self.assertNotIn("--trusted-local-execution", args)


class AtomicWriteTests(Base):
    def test_symlinked_destination_is_rejected_and_target_untouched(self):
        victim = self.root / "victim.txt"; victim.write_text("keep")
        os.symlink(victim, self.root / ".mcp.json")
        with self.assertRaises(cc.IntegrationConflict):
            cc.install(self.root)
        self.assertEqual(victim.read_text(), "keep")
        self.assertFalse((self.root / ".claude").exists())  # rejected during planning, nothing written

    def test_symlinked_skill_file_and_backup_source_are_rejected(self):
        victim = self.root / "victim.txt"; victim.write_text("keep")
        (self.root / ".claude/skills/vep").mkdir(parents=True)
        os.symlink(victim, self.root / ".claude/skills/vep/SKILL.md")
        r = cc.install(self.root, force=True)
        self.assertEqual(r["status"], "CONFLICT")  # --force does not override a symlink: it is never written through
        self.assertEqual(victim.read_text(), "keep")
        self.assertFalse((self.root / ".mcp.json").exists())

    def test_predictable_temp_name_cannot_hijack_the_write(self):
        victim = self.root / "victim.txt"; victim.write_text("keep")
        os.symlink(victim, self.root / f".mcp.json.vep-tmp-{os.getpid()}")  # the old, predictable name
        cc.install(self.root)
        self.assertEqual(victim.read_text(), "keep")
        self.assertIn("vep", json.loads((self.root / ".mcp.json").read_text())["mcpServers"])

    def test_interrupted_write_preserves_the_previous_destination(self):
        p = self.root / "f.json"; p.write_text("old"); os.chmod(p, 0o600)
        with mock.patch.object(cc.os, "fsync", side_effect=OSError("io")):
            with self.assertRaises(OSError):
                cc._atomic_write(p, b"new", 0o600)
        self.assertEqual(p.read_text(), "old")
        self.assertEqual([x for x in self.root.iterdir() if ".vep-tmp" in x.name], [])

    def test_partial_write_is_detected(self):
        p = self.root / "f.json"; p.write_text("old")
        real = os.write
        with mock.patch.object(cc.os, "write", side_effect=lambda fd, b: real(fd, b[:1]) if len(b) > 1 else real(fd, b)):
            cc._atomic_write(p, b"complete-content", 0o600)  # short writes are looped, not truncated
        self.assertEqual(p.read_bytes(), b"complete-content")

    def test_temp_file_is_private_from_creation(self):
        seen = []
        real = cc.os.replace
        def spy(src, dst):
            seen.append(mode(Path(src))); return real(src, dst)
        with mock.patch.object(cc.os, "replace", side_effect=spy):
            cc._atomic_write(self.root / "a.json", b"{}", 0o600)
        self.assertEqual(seen[0] & 0o077, 0)
        # and mkstemp (exclusive, unpredictable) is what creates it
        with mock.patch.object(cc.tempfile, "mkstemp", wraps=cc.tempfile.mkstemp) as ms:
            cc._atomic_write(self.root / "b.json", b"{}", 0o600)
        self.assertEqual(ms.call_count, 1)

    def test_concurrent_installers_do_not_corrupt_each_other(self):
        errs = []
        def run():
            try:
                for _ in range(5):
                    cc.install(self.root)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run) for _ in range(4)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errs, [])
        json.loads((self.root / ".mcp.json").read_text()); json.loads((self.root / ".claude/settings.json").read_text())
        self.assertEqual([p for p in self.root.rglob("*") if ".vep-tmp" in p.name], [])

    def test_plugin_files_are_valid_and_private_where_credential_capable(self):
        out = self.root / "plug"
        cc.write_plugin(out, version="0.0.0")
        self.assertEqual(mode(out / ".mcp.json") & 0o077, 0)
        json.loads((out / ".claude-plugin/plugin.json").read_text())
        self.assertTrue(mode(out / "hooks/vep_guard.py") & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
