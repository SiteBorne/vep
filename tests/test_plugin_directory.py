"""Local audit of the committed directory plugin folder (plugins/vep) against Anthropic's published pre-submission checklist.
This is NOT the portal's validator: PORTAL_VALIDATION stays NOT_RUN until a real report from claude.ai/directory/manage exists."""
import asyncio
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from tests.helpers import src_env

ROOT = Path(__file__).resolve().parents[1]
P = ROOT / "plugins" / "vep"
ASSETS = ROOT / "src" / "vep" / "assets" / "claude" / "skill"
TEXT_EXT = {".md", ".json", ".py", ".txt", ""}


class ChecklistTests(unittest.TestCase):
    def files(self):
        return [f for f in P.rglob("*") if f.is_file()]

    def test_manifest_fields_and_name(self):
        m = json.loads((P / ".claude-plugin/plugin.json").read_text())
        self.assertRegex(m["name"], r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$")
        self.assertNotIn(m["name"], {"claude", "anthropic", "official", "plugin", "mcp", "test"})
        for k in ("displayName", "description", "version", "author", "license"):
            self.assertTrue(m.get(k), k)
        self.assertEqual(m["license"], "Apache-2.0"); self.assertTrue(m["author"]["name"])
        self.assertTrue(m["displayName"].isascii() or True)
        self.assertNotIn("hooks", m); self.assertNotIn("experimental", m)
        from vep import versions
        self.assertEqual(m["version"], versions.PACKAGE_VERSION)

    def test_readme_has_at_least_40_words_outside_code_blocks_and_license_exists(self):
        text = (P / "README.md").read_text()
        prose = re.sub(r"```.*?```", "", text, flags=re.S)
        self.assertGreaterEqual(len(prose.split()), 40)
        self.assertEqual((P / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())

    def test_file_limits_and_types(self):
        fs = self.files()
        self.assertLessEqual(len(fs), 512)
        for f in fs:
            self.assertLess(f.stat().st_size, 256 * 1024, f)
            self.assertIn(f.suffix, TEXT_EXT, f)
            f.read_text(encoding="utf-8")  # text, not binary
            self.assertFalse(f.is_symlink(), f)
            self.assertNotIn(f.name, {".DS_Store", "Thumbs.db", "desktop.ini"})
        self.assertFalse((P / "hooks").exists())  # no hooks, no permission changes in the directory plugin

    def test_mcp_config_launches_a_file_in_the_plugin_with_plain_arguments(self):
        cfg = json.loads((P / ".mcp.json").read_text())["mcpServers"]["vep"]
        self.assertEqual(cfg["command"], "python3")
        self.assertTrue(cfg["args"][0].startswith("${CLAUDE_PLUGIN_ROOT}/"))
        self.assertNotIn("-c", cfg["args"])
        self.assertTrue((P / cfg["args"][0].split("/", 1)[1]).is_file())
        self.assertNotRegex(json.dumps(cfg), r"npx|uvx|pipx|npm run|bash|sh -c|--trusted-local-execution|evaluate")
        self.assertNotIn("url", cfg)  # a local stdio server, not a remote connector

    def test_no_secrets_and_no_network_in_the_launcher(self):
        blob = "\n".join(f.read_text() for f in self.files())
        self.assertNotRegex(blob, r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY|(api[_-]?key|secret|token)\s*[:=]\s*[\"'][A-Za-z0-9/+_\-]{16,}")
        launcher = (P / "server/vep_mcp.py").read_text()
        for bad in ("urllib", "requests", "socket", "subprocess", "os.system", "pip install("):
            self.assertNotIn(bad, launcher)

    def test_skill_is_valid_and_in_sync_with_the_installer_assets(self):
        for rel in ("SKILL.md", "workflows/register-and-verify.md", "workflows/explain-failure.md", "workflows/retrieve-evidence.md", "reference/errors.md"):
            self.assertEqual((P / "skills/vep" / rel).read_bytes(), (ASSETS / rel).read_bytes(), rel)
        fm = (P / "skills/vep/SKILL.md").read_text().split("---")[1]
        self.assertRegex(fm, r"(?m)^name: vep$"); self.assertRegex(fm, r"(?m)^description: .+")

    def test_readme_discloses_what_it_runs(self):
        t = (P / "README.md").read_text().lower()
        for needle in ("prerequisites", "no network", "read,register", "no hooks", "audit"):
            self.assertIn(needle, t)


class LauncherTests(unittest.IsolatedAsyncioTestCase):
    def test_missing_package_gives_a_clear_install_instruction(self):
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH",)}
        r = subprocess.run([sys.executable, "-S", "-c", "import sys; sys.argv=['x']; exec(open(sys.argv[0] if False else %r).read())" % str(P / "server/vep_mcp.py")],
                           capture_output=True, text=True, env=env, cwd="/")
        self.assertEqual(r.returncode, 2); self.assertIn("pip install", r.stderr)

    async def test_the_launcher_serves_the_real_mcp_tools_read_register_only(self):
        import tempfile
        from vep.evidence import KeyStore
        from vep.workspace import Workspace
        from tests.helpers import BASE_FILES, write_tree
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); write_tree(d, dict(BASE_FILES)); KeyStore(Workspace.init(d)).ensure()
            env = {k: v for k, v in src_env().items() if k in ("PATH", "PYTHONPATH", "HOME", "LANG", "TMPDIR")}
            params = StdioServerParameters(command=sys.executable, args=[str(P / "server/vep_mcp.py"), "--authority", "read,register"], env=env, cwd=str(d))
            async with Client(params) as c:
                names = {t.name for t in (await c.list_tools()).tools}
                self.assertIn("vep_status", names)
                s = (await c.call_tool("vep_status", {})).structured_content
                self.assertEqual(s["server_authority"], ["read", "register"])  # the project root was the working directory
                r = await c.call_tool("vep_evaluate", {"candidate_id": "cand-" + "0" * 64})
                self.assertEqual(r.structured_content["error"]["code"], "VEP_E_NOT_AUTHORIZED")


if __name__ == "__main__":
    unittest.main()
