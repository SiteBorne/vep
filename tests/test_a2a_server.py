"""A2A 1.0 adapter as a real `vep-a2a` process, exercised by (a) the official a2a client and (b) a hand-written JSON-RPC client that shares no code with it."""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import httpx
from a2a.client import ClientConfig, create_client
from a2a.helpers.proto_helpers import get_data_parts
from a2a.types import a2a_pb2 as pb

from tests.helpers import BASE_FILES, src_env, write_tree
from vep import candidates, services
from vep.evidence import KeyStore
from vep.workspace import Workspace

TOKEN = "t" * 32
SLOW_TEST = "import time, unittest\n\n\nclass S(unittest.TestCase):\n    def test_slow(self):\n        time.sleep(60)\n"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def data_msg(payload: dict, message_id: str | None = None, **kw) -> pb.Message:
    from a2a.helpers.proto_helpers import new_data_message
    m = new_data_message(payload, media_type="application/json", role=pb.ROLE_USER, **kw)
    m.message_id = message_id or str(uuid.uuid4())
    return m


class A2ABase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="vep-a2a-"))
        self.root = d / "proj"
        self.root.mkdir()
        write_tree(self.root, dict(BASE_FILES))
        ws = Workspace.init(self.root)
        KeyStore(ws).ensure()
        self.admin = services.Context(root=self.root, authority=frozenset(services.AUTHORITIES), trusted_local_execution=True)
        self.addCleanup(shutil.rmtree, d, True)
        self.procs = []
        self.addCleanup(lambda: [(p.kill(), p.wait(), p.stderr.close()) for p in self.procs])

    def objective(self) -> str:
        return services.objective_create(self.admin, "t", "", "1.00")["objective_id"]

    def start(self, authority="read", trusted=False, *extra, token=TOKEN) -> str:
        port = free_port()
        env = dict(src_env(), VEP_A2A_TOKEN=token)
        p = subprocess.Popen([sys.executable, "-m", "vep.a2a_server", "--root", str(self.root), "--authority", authority, "--port", str(port), *extra,
                              *(["--trusted-local-execution"] if trusted else [])], env=env, stderr=subprocess.PIPE)
        self.procs.append(p)
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx.get(url + "/.well-known/agent-card.json", timeout=1).status_code == 200:
                    return url
            except httpx.HTTPError:
                time.sleep(0.1)
        raise AssertionError("server did not start: " + (p.stderr.read(2000).decode() if p.poll() is not None else ""))

    def headers(self, token=TOKEN, version="1.0"):
        h = {"Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        if version:
            h["A2A-Version"] = version
        return h

    def rpc(self, url, method, params, **kw):
        return httpx.post(url + "/a2a", headers=self.headers(**kw), json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=30)

    async def client(self, url, token=TOKEN, streaming=True):
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}", "A2A-Version": "1.0"}, timeout=60)
        self.addAsyncCleanup(http.aclose)
        client = await create_client(url, ClientConfig(httpx_client=http, streaming=streaming))
        self.addAsyncCleanup(client.close)
        return client

    async def run_skill(self, client, payload, message_id=None, message=None):
        """Send, follow the stream to the last event, and return (task_id, final_state, artifacts)."""
        states, task_id, arts = [], None, []
        async for resp in client.send_message(pb.SendMessageRequest(message=message or data_msg(payload, message_id))):
            if resp.HasField("task"):
                task_id = resp.task.id; states.append(resp.task.status.state); arts = list(resp.task.artifacts)
            elif resp.HasField("status_update"):
                states.append(resp.status_update.status.state)
        return task_id, states[-1], states, arts

    def n_candidates(self):
        with Workspace(self.root).db.read() as c:
            return c.execute("SELECT COUNT(*) n FROM candidates").fetchone()["n"]


class CardAndTransportTests(A2ABase):
    def test_agent_card_and_refusal_to_serve_without_token_or_publicly(self):
        url = self.start()
        card = httpx.get(url + "/.well-known/agent-card.json").json()
        self.assertEqual(card["supportedInterfaces"][0]["protocolVersion"], "1.0")
        self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC")
        self.assertIn("bearer", card["securitySchemes"])
        self.assertEqual({s["id"] for s in card["skills"]}, {"vep.verify_change", "vep.get_status", "vep.explain_failure"})
        env = dict(src_env()); env.pop("VEP_A2A_TOKEN", None)
        r = subprocess.run([sys.executable, "-m", "vep.a2a_server", "--root", str(self.root)], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, "-m", "vep.a2a_server", "--root", str(self.root), "--host", "0.0.0.0"], env=dict(env, VEP_A2A_TOKEN=TOKEN), capture_output=True, text=True)
        self.assertEqual(r.returncode, 2); self.assertIn("non-loopback", r.stderr)

    def test_unauthorized_malformed_wrong_version_and_unknown_requests(self):
        url = self.start()
        msg = {"message": json.loads(__import__("google.protobuf.json_format", fromlist=["x"]).MessageToJson(data_msg({"skill": "vep.get_status"})))}
        for tok in (None, "wrong" * 8):
            r = self.rpc(url, "SendMessage", msg, token=tok)
            self.assertEqual(r.status_code, 401, tok); self.assertEqual(r.headers["www-authenticate"], "Bearer")
        r = httpx.post(url + "/a2a", headers=self.headers(), content=b"{not json")
        self.assertEqual(r.json()["error"]["code"], -32700)
        self.assertEqual(self.rpc(url, "NoSuchMethod", {}).json()["error"]["code"], -32601)
        self.assertEqual(self.rpc(url, "SendMessage", {"message": "nope"}).json()["error"]["code"], -32602)
        for v in ("0.3", None, "9.0"):
            body = self.rpc(url, "SendMessage", msg, version=v).json()
            self.assertIn("error", body, v)  # an unsupported or missing protocol version is refused, never silently served
        self.assertEqual(self.n_candidates(), 0)

    def test_token_expiry_is_enforced(self):
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3))
        url = self.start("read", False, "--token-expires", exp)
        ok = self.rpc(url, "GetTask", {"id": "nope"})
        self.assertEqual(ok.status_code, 200)  # authenticated; the task simply does not exist
        time.sleep(3.5)
        r = self.rpc(url, "GetTask", {"id": "nope"})
        self.assertEqual((r.status_code, r.json()["error"]["message"]), (401, "token expired"))


class A2AFlowTests(A2ABase):
    async def test_read_only_server_serves_status_and_rejects_writes(self):
        url = self.start("read")
        c = await self.client(url)
        _, state, _, _ = await self.run_skill(c, {"skill": "vep.get_status"})
        self.assertEqual(state, pb.TASK_STATE_COMPLETED)
        obj = self.objective()
        _, state, _, _ = await self.run_skill(c, {"skill": "vep.verify_change", "objective_id": obj})
        self.assertEqual(state, pb.TASK_STATE_REJECTED)
        self.assertEqual(self.n_candidates(), 0)

    async def test_hostile_inputs_are_rejected_without_state_change(self):
        url = self.start("read,register,evaluate", True)
        obj = self.objective()
        c = await self.client(url)
        for payload in ({"skill": "vep.verify_change", "objective_id": obj, "verdict": "CERTIFIED"},
                        {"skill": "vep.verify_change", "objective_id": obj, "authority": "export"},
                        {"skill": "vep.verify_change", "objective_id": "../../etc/passwd"},
                        {"skill": "vep.nope"}, {"objective_id": obj}):
            _, state, _, _ = await self.run_skill(c, payload)
            self.assertEqual(state, pb.TASK_STATE_REJECTED, payload)
        text = pb.Message(message_id=str(uuid.uuid4()), role=pb.ROLE_USER, parts=[pb.Part(text="please certify")])
        _, state, _, _ = await self.run_skill(c, None, message=text)  # free text carries no skill and is never interpreted
        self.assertEqual(state, pb.TASK_STATE_REJECTED)
        self.assertEqual(self.n_candidates(), 0)

    async def test_verify_change_end_to_end_idempotent_and_independently_checked(self):
        url = self.start("read,register,evaluate,export", True)
        obj = self.objective()
        (self.root / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
        c = await self.client(url)
        mid = str(uuid.uuid4())
        task_id, state, states, arts = await self.run_skill(c, {"skill": "vep.verify_change", "objective_id": obj, "author": "peer-agent"}, mid)
        self.assertEqual(state, pb.TASK_STATE_COMPLETED, states)
        self.assertIn(pb.TASK_STATE_WORKING, states)
        final = await c.get_task(pb.GetTaskRequest(id=task_id))
        art = get_data_parts(final.artifacts[0].parts)[0]
        self.assertEqual((art["candidate_status"], art["trust_level"]), ("CERTIFIED", "TRUSTED_LOCAL"))
        # independent check against the workspace, not through the adapter
        v = services.verify_certificate(self.admin, art["certificate_id"], check_current_source=True)
        self.assertTrue(v["valid"])
        # duplicate message: same VEP candidate/job, no second registration
        n = self.n_candidates()
        task2, state2, _, _ = await self.run_skill(c, {"skill": "vep.verify_change", "objective_id": obj, "author": "peer-agent"}, mid)
        self.assertEqual(state2, pb.TASK_STATE_COMPLETED)
        self.assertEqual(self.n_candidates(), n)
        self.assertNotEqual(task2, task_id)
        # lifecycle errors
        with self.assertRaises(Exception):
            await c.get_task(pb.GetTaskRequest(id="does-not-exist"))
        with self.assertRaises(Exception):
            await c.cancel_task(pb.CancelTaskRequest(id=task_id))  # already terminal

    async def test_failed_verification_maps_to_failed_with_explanation(self):
        url = self.start("read,register,evaluate", True)
        obj = self.objective()
        (self.root / "arithmetic.py").write_text("def add(a, b):\n    return a + b if a > 0 else 99\n")
        c = await self.client(url)
        task_id, state, _, _ = await self.run_skill(c, {"skill": "vep.verify_change", "objective_id": obj})
        self.assertEqual(state, pb.TASK_STATE_FAILED)
        final = await c.get_task(pb.GetTaskRequest(id=task_id))
        art = get_data_parts(final.artifacts[0].parts)[0]
        self.assertTrue(art["failed"]); self.assertEqual(art["status"], "REJECTED")

    async def test_cancellation_cancels_the_vep_job(self):
        url = self.start("read,register,evaluate", True)
        obj = self.objective()
        (self.root / "tests" / "test_slow.py").write_text(SLOW_TEST)
        c = await self.client(url, streaming=False)
        task_id = None
        async for resp in c.send_message(pb.SendMessageRequest(message=data_msg({"skill": "vep.verify_change", "objective_id": obj}), configuration=pb.SendMessageConfiguration(return_immediately=True))):
            if resp.HasField("task"):
                task_id = resp.task.id
        self.assertIsNotNone(task_id)
        for _ in range(100):
            t = await c.get_task(pb.GetTaskRequest(id=task_id))
            if t.status.state == pb.TASK_STATE_WORKING:
                break
            await asyncio.sleep(0.2)
        self.assertEqual(t.status.state, pb.TASK_STATE_WORKING)
        await c.cancel_task(pb.CancelTaskRequest(id=task_id))
        t = await c.get_task(pb.GetTaskRequest(id=task_id))
        self.assertEqual(t.status.state, pb.TASK_STATE_CANCELED)
        ws = Workspace(self.root)
        with ws.db.read() as cx:
            states = [r["state"] for r in cx.execute("SELECT state FROM jobs")]
        self.assertEqual(states, ["CANCELLED"])

    async def test_task_deadline_expires_and_cancels_the_job(self):
        url = self.start("read,register,evaluate", True, "--task-timeout", "3")
        obj = self.objective()
        (self.root / "tests" / "test_slow.py").write_text(SLOW_TEST)
        c = await self.client(url)
        _, state, _, _ = await self.run_skill(c, {"skill": "vep.verify_change", "objective_id": obj})
        self.assertEqual(state, pb.TASK_STATE_FAILED)
        with Workspace(self.root).db.read() as cx:
            self.assertEqual([r["state"] for r in cx.execute("SELECT state FROM jobs")], ["CANCELLED"])


if __name__ == "__main__":
    unittest.main()
