"""Claude Agent SDK adapter, offline: configuration contract, drift against the live MCP server, hook decisions. No model call is made."""
import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions
from mcp.client.client import Client

from tests.test_mcp_server import params, project
from vep import agent_sdk


class AgentSdkContract(unittest.IsolatedAsyncioTestCase):
    def test_options_reflect_authority_and_deny_the_rest(self):
        o = agent_sdk.vep_options("/tmp", authority=("read", "register"), max_budget_usd=0.5)
        self.assertIsInstance(o, ClaudeAgentOptions)
        self.assertIn("mcp__vep__vep_status", o.allowed_tools); self.assertIn("mcp__vep__vep_candidate_register", o.allowed_tools)
        self.assertIn("mcp__vep__vep_evaluate", o.disallowed_tools); self.assertIn("mcp__vep__vep_export_evidence", o.disallowed_tools)
        self.assertFalse(set(o.allowed_tools) & set(o.disallowed_tools))
        srv = o.mcp_servers["vep"]
        self.assertEqual((srv["type"], srv["args"][:2]), ("stdio", ["-m", "vep.mcp_server"]))
        self.assertNotIn("--trusted-local-execution", srv["args"])
        self.assertEqual(o.max_budget_usd, 0.5); self.assertIn(o.permission_mode, (None, "default"))  # never bypass permissions
        e = agent_sdk.vep_options("/tmp", authority=("read", "register", "evaluate", "export"), trusted_local=True)
        self.assertIn("--trusted-local-execution", e.mcp_servers["vep"]["args"]); self.assertEqual(e.disallowed_tools, [])

    def test_invalid_authority_is_refused(self):
        for bad in (("register",), ("read", "root"), ()):
            with self.assertRaises(ValueError):
                agent_sdk.vep_options("/tmp", authority=bad)
        with self.assertRaises(ValueError):
            agent_sdk.vep_options("/tmp", authority=("read",), trusted_local=True)

    async def test_tool_table_matches_the_live_server(self):
        root = project()
        self.addCleanup(shutil.rmtree, root.parent, True)
        async with Client(params(root, "read")) as c:
            live = {t.name for t in (await c.list_tools()).tools}
        self.assertEqual(live, set(agent_sdk.TOOL_AUTHORITY))

    async def test_guard_hook_decisions(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            deny = await agent_sdk.guard_hook({"tool_name": "Write", "tool_input": {"file_path": f"{d}/.vep/x"}, "cwd": d}, "id", None)
            self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")
            deny = await agent_sdk.guard_hook({"tool_name": "Bash", "tool_input": {"command": "vep certify --candidate c"}, "cwd": d}, "id", None)
            self.assertEqual(deny["hookSpecificOutput"]["permissionDecision"], "deny")
            self.assertEqual(await agent_sdk.guard_hook({"tool_name": "Edit", "tool_input": {"file_path": f"{d}/a.py"}, "cwd": d}, "id", None), {})


if __name__ == "__main__":
    unittest.main()
