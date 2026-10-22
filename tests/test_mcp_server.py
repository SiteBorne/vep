"""MCP server over real stdio with the official MCP client (protocol 2026-07-28): authority, idempotency, bounds, full flow, independent check."""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters

from tests.helpers import BASE_FILES, src_env, write_tree
from vep import conformance, trustpolicy
from vep.evidence import KeyStore
from vep.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
TOOLS = {"vep_status", "vep_objective_create", "vep_candidate_register", "vep_evaluate", "vep_job_status", "vep_candidate_state", "vep_verify_certificate",
         "vep_export_evidence", "vep_reuse_evidence", "vep_budget_status", "vep_explain_failure", "vep_read_artifact"}


def project() -> Path:
    d = Path(tempfile.mkdtemp(prefix="vep-mcp-"))
    root = d / "proj"
    root.mkdir()
    write_tree(root, dict(BASE_FILES))
    ws = Workspace.init(root)
    KeyStore(ws).ensure()
    return root


def params(root: Path, authority: str, trusted: bool = False) -> StdioServerParameters:
    env = {k: v for k, v in src_env().items() if k in ("PATH", "PYTHONPATH", "HOME", "LANG", "TMPDIR")}
    args = ["-m", "vep.mcp_server", "--root", str(root), "--authority", authority] + (["--trusted-local-execution"] if trusted else [])
    return StdioServerParameters(command=sys.executable, args=args, env=env)


def sc(r):
    return r.structured_content


class McpTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = project()
        self.addCleanup(shutil.rmtree, self.root.parent, True)

    async def test_protocol_version_and_tool_surface(self):
        async with Client(params(self.root, "read")) as c:
            self.assertEqual(c.protocol_version, "2026-07-28")
            tools = {t.name: t for t in (await c.list_tools()).tools}
            self.assertEqual(set(tools), TOOLS)
            for name, t in tools.items():
                self.assertTrue(t.input_schema["type"] == "object" and t.output_schema, name)  # schemas for input and output on every tool
            self.assertTrue(tools["vep_status"].annotations.read_only_hint)
            self.assertFalse(tools["vep_evaluate"].annotations.read_only_hint)
            s = sc(await c.call_tool("vep_status", {}))
            self.assertEqual((s["ok"], s["evaluation_enabled"], s["server_authority"]), (True, False, ["read"]))
            self.assertLess(len(json.dumps(s)), 2000)  # compact by default

    async def test_authority_is_enforced_by_the_operator_not_the_caller(self):
        async with Client(params(self.root, "read")) as c:
            for tool, args in (("vep_objective_create", {"title": "t"}), ("vep_candidate_register", {"objective_id": "obj-" + "0" * 64}),
                               ("vep_evaluate", {"candidate_id": "cand-" + "0" * 64}), ("vep_export_evidence", {"certificate_id": "cert-" + "0" * 64})):
                r = await c.call_tool(tool, {**args, "authority": "evaluate,register,export"})  # a caller cannot grant itself anything
                self.assertTrue(r.is_error, tool)
                self.assertEqual(sc(r)["error"]["code"], "VEP_E_NOT_AUTHORIZED", tool)
        async with Client(params(self.root, "read,register,evaluate,export", trusted=False)) as c:
            o = sc(await c.call_tool("vep_objective_create", {"title": "t"}))
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"]}))
            r = await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]})
            self.assertEqual(sc(r)["error"]["code"], "VEP_E_EVALUATION_DISABLED")  # no unisolated execution without the operator's explicit flag

    async def test_invalid_and_hostile_arguments_get_stable_codes_and_change_nothing(self):
        async with Client(params(self.root, "read,register")) as c:
            for tool, args in (("vep_candidate_state", {"candidate_id": "../../etc/passwd"}), ("vep_job_status", {"job_id": "job-xyz"}),
                               ("vep_job_status", {}), ("vep_read_artifact", {"digest": "../../keys"}), ("vep_budget_status", {"objective_id": "obj-1; DROP TABLE"}),
                               ("vep_objective_create", {"title": "x" * 500}), ("vep_candidate_register", {"objective_id": "cand-" + "0" * 64})):
                r = await c.call_tool(tool, args)
                self.assertTrue(r.is_error, (tool, args))
                self.assertIn(sc(r)["error"]["code"], ("VEP_E_INVALID_ARGUMENT",), (tool, args))
            o = sc(await c.call_tool("vep_objective_create", {"title": "t"}))
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"], "certified": True, "verdict": "PASS"}))  # extra fields are not a verdict
            self.assertEqual(sc(await c.call_tool("vep_candidate_state", {"candidate_id": cand["candidate_id"]}))["status"], "POLICY_CHECKED")
            nf = await c.call_tool("vep_candidate_state", {"candidate_id": "cand-" + "f" * 64})
            self.assertEqual(sc(nf)["error"]["code"], "VEP_E_NOT_FOUND")

    async def test_idempotency_and_bounded_resources(self):
        async with Client(params(self.root, "read,register")) as c:
            a = sc(await c.call_tool("vep_objective_create", {"title": "t", "idempotency_key": "k1"}))
            b = sc(await c.call_tool("vep_objective_create", {"title": "t", "idempotency_key": "k1"}))
            self.assertEqual(a["objective_id"], b["objective_id"])
            self.assertTrue(b["idempotent_replay"])
            r1 = sc(await c.call_tool("vep_candidate_register", {"objective_id": a["objective_id"], "idempotency_key": "c1"}))
            r2 = sc(await c.call_tool("vep_candidate_register", {"objective_id": a["objective_id"], "idempotency_key": "c1"}))
            self.assertEqual(r1["candidate_id"], r2["candidate_id"])
            res = await c.read_resource(f"vep://objective/{a['objective_id']}")
            self.assertLess(len(res.contents[0].text), 4000)
            self.assertEqual(json.loads((await c.read_resource("vep://version")).contents[0].text)["versions"]["package"], json.loads(
                (await c.call_tool("vep_status", {})).content[0].text)["versions"]["package"])
            h = json.loads((await c.read_resource(f"vep://history/{r1['candidate_id']}")).contents[0].text)
            self.assertEqual(h["entries"][0]["to"], "PROPOSED")

    async def test_full_flow_with_independent_verification(self):
        async with Client(params(self.root, "read,register,evaluate,export", trusted=True)) as c:
            o = sc(await c.call_tool("vep_objective_create", {"title": "add feature", "budget": "1.00"}))
            (self.root / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"], "author": "claude"}))
            self.assertEqual(cand["policy_violations"], [])
            ev = sc(await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]}))
            self.assertTrue(ev["ok"])
            again = sc(await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]}))
            self.assertEqual(again["job_id"], ev["job_id"])  # idempotent
            deadline = time.time() + 120
            while time.time() < deadline:
                js = sc(await c.call_tool("vep_job_status", {"candidate_id": cand["candidate_id"]}))
                if js["state"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                    break
                await asyncio.sleep(0.5)
            self.assertEqual((js["state"], js["result"]["candidate_status"]), ("SUCCEEDED", "CERTIFIED"))
            cert = js["result"]["certificate_id"]
            v = sc(await c.call_tool("vep_verify_certificate", {"certificate_id": cert, "check_current_source": True}))
            self.assertTrue(v["valid"])
            self.assertEqual(v["assurance"], "WORKSPACE_KEY_REGISTRY")
            exp = sc(await c.call_tool("vep_export_evidence", {"certificate_id": cert}))
            self.assertEqual(exp["bundle_version"], 2)
            self.assertLess(len(json.dumps(exp)), 1500)  # a handle, not the bundle
            bundle = json.loads((self.root / exp["path"]).read_text())
            self.assertEqual(set(bundle), {"bundle_version", "certificate_envelope", "evidence_envelope"})
            # independent verification: relying-party policy built OUTSIDE the server, checked in Python and in Node
            ws = Workspace(self.root)
            with ws.db.read() as cx:
                raw = bytes.fromhex(cx.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
            snap = sc(await c.call_tool("vep_candidate_state", {"candidate_id": cand["candidate_id"]}))["snapshot_id"]
            pol = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap)
            self.assertTrue(trustpolicy.verify_authorized(bundle, pol, "2099-01-01T00:00:00Z")["valid"])
            if NODE:
                d = self.root.parent
                (d / "p.json").write_text(json.dumps(pol))
                out = json.loads(subprocess.run([NODE, str(ROOT / "conformance/node/verify.mjs"), "authorized", str(self.root / exp["path"]), str(d / "p.json"), "2099-01-01T00:00:00Z"],
                                                capture_output=True, text=True).stdout)
                self.assertEqual((out["valid"], out["assurance"]), (True, "AUTHORIZED"))
            b = sc(await c.call_tool("vep_budget_status", {"objective_id": o["objective_id"]}))
            self.assertEqual(b["settled"], "0.001")

    async def test_reuse_evidence_needs_authority_and_reports_no_match_honestly(self):
        async with Client(params(self.root, "read,register")) as c:
            o = sc(await c.call_tool("vep_objective_create", {"title": "t"}))
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"]}))
            r = await c.call_tool("vep_reuse_evidence", {"candidate_id": cand["candidate_id"]})
            self.assertEqual(sc(r)["error"]["code"], "VEP_E_NOT_AUTHORIZED")
        async with Client(params(self.root, "read,evaluate")) as c:  # executes nothing, so the trusted-local switch is not needed
            r = sc(await c.call_tool("vep_reuse_evidence", {"candidate_id": cand["candidate_id"]}))
            self.assertEqual((r["ok"], r["reused"], r["next_action"]), (True, False, "vep_evaluate"))

    async def test_failure_is_explained_with_invariant_remedy_and_handles(self):
        async with Client(params(self.root, "read,register,evaluate", trusted=True)) as c:
            o = sc(await c.call_tool("vep_objective_create", {"title": "break it"}))
            (self.root / "arithmetic.py").write_text("def add(a, b):\n    return a + b if a > 0 else 99\n")  # breaks exactly one of the two protected tests
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"]}))
            sc(await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]}))
            for _ in range(240):
                js = sc(await c.call_tool("vep_job_status", {"candidate_id": cand["candidate_id"]}))
                if js["state"] in ("SUCCEEDED", "FAILED"):
                    break
                await asyncio.sleep(0.5)
            self.assertEqual(js["result"]["candidate_status"], "REJECTED")
            self.assertEqual(js["next_action"], "vep_explain_failure")
            ex = sc(await c.call_tool("vep_explain_failure", {"candidate_id": cand["candidate_id"]}))
            self.assertTrue(ex["failed"])
            self.assertEqual(ex["reason_code"], "tests failed")
            self.assertGreaterEqual(ex["failing_tests_total"], 1)
            self.assertTrue(any("test_add" in t for t in ex["failing_tests_preview"]))
            page = sc(await c.call_tool("vep_read_artifact", {"digest": ex["handles"]["stderr"], "limit": 500}))
            self.assertLessEqual(len(page["text"]), 500)
            self.assertGreater(page["total_bytes"], 0)
            other = await c.call_tool("vep_read_artifact", {"digest": "0" * 64})
            self.assertEqual(sc(other)["error"]["code"], "VEP_E_NOT_FOUND")  # only digests referenced by this workspace's evidence are readable


    async def test_a_change_that_breaks_every_test_is_explained_as_too_few_passing(self):
        async with Client(params(self.root, "read,register,evaluate", trusted=True)) as c:
            o = sc(await c.call_tool("vep_objective_create", {"title": "break all"}))
            (self.root / "arithmetic.py").write_text("def add(a, b):\n    return a - b\n")
            cand = sc(await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"]}))
            sc(await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]}))
            for _ in range(240):
                js = sc(await c.call_tool("vep_job_status", {"candidate_id": cand["candidate_id"]}))
                if js["state"] in ("SUCCEEDED", "FAILED"):
                    break
                await asyncio.sleep(0.5)
            ex = sc(await c.call_tool("vep_explain_failure", {"job_id": js["job_id"]}))
            self.assertEqual((ex["failed"], ex["reason_code"]), (True, "TOO_FEW_PASSING_TESTS"))
            self.assertIn("remedy", ex)


class RemoteTransportTests(unittest.TestCase):
    def test_remote_http_is_refused_rather_than_offered_unauthenticated(self):
        r = subprocess.run([sys.executable, "-m", "vep.mcp_server", "--root", ".", "--transport", "streamable-http"], capture_output=True, text=True, env=src_env())
        self.assertEqual(r.returncode, 2)
        self.assertIn("not qualified", r.stderr)

    def test_unknown_authority_is_refused(self):
        r = subprocess.run([sys.executable, "-m", "vep.mcp_server", "--authority", "root"], capture_output=True, text=True, env=src_env())
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
