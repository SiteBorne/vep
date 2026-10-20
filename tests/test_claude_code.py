import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vep import claude_code as cc
from vep.cli import main as cli_main

GUARD = Path(cc.__file__).parent / "assets" / "claude" / "vep_guard.py"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.addCleanup(self._t.cleanup)

    def test_install_status_uninstall_roundtrip_preserves_user_content(self):
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}))
        (self.root / "CLAUDE.md").write_text("# mine\n\nhello\n")
        (self.root / ".claude").mkdir()
        (self.root / ".claude/settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"]}, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "true"}]}]}}))
        r = cc.install(self.root)
        self.assertEqual(r["status"], "INSTALLED")
        mcp = json.loads((self.root / ".mcp.json").read_text())
        self.assertIn("other", mcp["mcpServers"]); self.assertIn("vep", mcp["mcpServers"])
        self.assertIn("--authority", mcp["mcpServers"]["vep"]["args"])
        self.assertNotIn("--trusted-local-execution", mcp["mcpServers"]["vep"]["args"])
        st = json.loads((self.root / ".claude/settings.json").read_text())
        self.assertEqual(st["permissions"], {"allow": ["Bash(ls)"]}); self.assertEqual(len(st["hooks"]["PreToolUse"]), 2)
        self.assertTrue(all(v == "ok" for v in cc.status(self.root)["components"].values()))
        self.assertEqual(cc.install(self.root)["status"], "INSTALLED")  # idempotent
        self.assertTrue(all(p["action"] == "unchanged" for p in cc.install(self.root)["plan"]))
        u = cc.uninstall(self.root)
        self.assertEqual(u["status"], "UNINSTALLED"); self.assertEqual(u["kept"], [])
        self.assertEqual(json.loads((self.root / ".mcp.json").read_text()), {"mcpServers": {"other": {"command": "x"}}})
        self.assertEqual((self.root / "CLAUDE.md").read_text(), "# mine\n\nhello\n")
        st = json.loads((self.root / ".claude/settings.json").read_text())
        self.assertEqual(len(st["hooks"]["PreToolUse"]), 1)
        self.assertFalse((self.root / ".claude/skills").exists()); self.assertFalse((self.root / cc.MANIFEST).exists())

    def test_foreign_vep_server_is_a_conflict_unless_forced_with_backup(self):
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"vep": {"command": "mine"}}}))
        r = cc.install(self.root)
        self.assertEqual(r["status"], "CONFLICT")
        self.assertEqual(json.loads((self.root / ".mcp.json").read_text())["mcpServers"]["vep"], {"command": "mine"})
        self.assertFalse((self.root / ".claude").exists())  # nothing partially written
        r = cc.install(self.root, force=True)
        self.assertEqual(r["status"], "INSTALLED"); self.assertTrue(r["backups"])
        bak = next((self.root / ".claude/vep-backups").rglob(".mcp.json"))
        self.assertEqual(json.loads(bak.read_text())["mcpServers"]["vep"], {"command": "mine"})

    def test_modified_installed_file_is_conflict_and_kept_on_uninstall(self):
        cc.install(self.root)
        skill = self.root / ".claude/skills/vep/SKILL.md"
        skill.write_text(skill.read_text() + "\nmy edit\n")
        self.assertEqual(cc.status(self.root)["components"][".claude/skills/vep/SKILL.md"], "modified")
        u = cc.uninstall(self.root)
        self.assertTrue(any("SKILL.md" in k for k in u["kept"])); self.assertTrue(skill.exists())

    def test_invalid_json_is_refused_without_changes(self):
        (self.root / ".mcp.json").write_text("{not json")
        with self.assertRaises(cc.IntegrationConflict):
            cc.install(self.root)
        self.assertEqual((self.root / ".mcp.json").read_text(), "{not json")

    def test_authority_is_operator_chosen_and_trusted_local_needs_evaluate(self):
        with self.assertRaises(cc.IntegrationConflict):
            cc.install(self.root, trusted_local=True)
        cc.install(self.root, authority=cc.AUTHORITY_EVALUATING, trusted_local=True)
        args = json.loads((self.root / ".mcp.json").read_text())["mcpServers"]["vep"]["args"]
        self.assertIn("--trusted-local-execution", args); self.assertIn("read,register,evaluate,export", args)

    def test_dry_run_changes_nothing(self):
        r = cc.install(self.root, dry_run=True)
        self.assertEqual(r["status"], "DRY_RUN"); self.assertEqual(list(self.root.iterdir()), [])

    def test_cli_exit_code_on_conflict(self):
        (self.root / ".mcp.json").write_text(json.dumps({"mcpServers": {"vep": {"command": "mine"}}}))
        self.assertEqual(cli_main(["claude", "install", "--root", str(self.root)]), 3)

    def test_plugin_layout(self):
        out = self.root / "plug"
        cc.write_plugin(out, version="9.9.9")
        m = json.loads((out / ".claude-plugin/plugin.json").read_text())
        self.assertEqual((m["name"], m["version"]), ("vep", "9.9.9"))
        for f in ("skills/vep/SKILL.md", ".mcp.json", "hooks/hooks.json", "hooks/vep_guard.py"):
            self.assertTrue((out / f).exists(), f)
        with self.assertRaises(cc.IntegrationConflict):
            cc.write_plugin(out, version="1")

    def test_skill_is_concise_and_links_resolve(self):
        cc.install(self.root)
        sk = self.root / ".claude/skills/vep"
        text = (sk / "SKILL.md").read_text()
        self.assertLess(len(text.splitlines()), 80)
        self.assertTrue(text.startswith("---\nname: vep\n"))
        import re
        for rel in re.findall(r"\]\(([^)]+\.md)\)", text):
            self.assertTrue((sk / rel).exists(), rel)
        from vep.services import ERROR_CODES
        errors = (sk / "reference/errors.md").read_text()
        for code in ERROR_CODES:
            self.assertIn(code, errors)


class GuardHookTests(unittest.TestCase):
    def run_hook(self, root, payload):
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(root))
        p = subprocess.run([sys.executable, str(GUARD)], input=json.dumps(payload), capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] if p.stdout.strip() else None

    def test_decisions(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            h = lambda tool, **inp: self.run_hook(d, {"tool_name": tool, "tool_input": inp, "cwd": d})
            self.assertEqual(h("Edit", file_path=f"{d}/.vep/vep.db"), "deny")
            self.assertEqual(h("Write", file_path=".vep/keys/x"), "deny")
            self.assertEqual(h("Edit", file_path=f"{d}/.vep/../.vep/a"), "deny")
            self.assertIsNone(h("Edit", file_path=f"{d}/src/a.py"))
            self.assertEqual(h("Bash", command="sqlite3 .vep/vep.db 'delete from x'"), "deny")
            self.assertEqual(h("Bash", command="rm -rf .vep"), "deny")
            self.assertEqual(h("Bash", command="vep run --candidate c --trusted-local-execution"), "deny")
            self.assertEqual(h("Bash", command="cd x && vep certify --candidate c"), "deny")
            self.assertEqual(h("Bash", command="vep --root . evaluate --candidate c"), "deny")
            self.assertIsNone(h("Bash", command="vep status --json"))
            self.assertIsNone(h("Bash", command="ls .vep"))
            self.assertIsNone(h("Bash", command="git status"))

    def test_unreadable_input_gives_no_decision(self):
        p = subprocess.run([sys.executable, str(GUARD)], input="garbage", capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
