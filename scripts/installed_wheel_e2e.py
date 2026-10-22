"""End-to-end proof against the INSTALLED wheel (not the source tree): MCP stdio and A2A, real protected evaluation, independent verification.

    python scripts/installed_wheel_e2e.py --out docs/evidence/installed-wheel-e2e.json [--wheel dist/x.whl]

Builds the wheel (unless given), installs it with the mcp and a2a extras into a fresh venv, then drives the installed `vep-mcp` / `vep-a2a`
entry points with the official MCP and A2A clients from that venv. Records pass/fail per step; nothing is mocked and no model is used.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DRIVER = r'''
import asyncio, json, os, shutil, signal, socket, subprocess, sys, tempfile, time, uuid
from pathlib import Path
import httpx
from mcp.client.client import Client
from mcp.client.stdio import StdioServerParameters
from a2a.client import ClientConfig, create_client
from a2a.helpers.proto_helpers import get_data_parts, new_data_message
from a2a.types import a2a_pb2 as pb
from google.protobuf.json_format import MessageToJson
import vep
from vep import trustpolicy, conformance, versions
from vep.workspace import Workspace
from vep.evidence import KeyStore

BIN = Path(sys.executable).parent
steps = []
def rec(name, ok, detail=""):
    steps.append({"step": name, "ok": bool(ok), "detail": str(detail)[:300]})
    print(("PASS " if ok else "FAIL ") + name, str(detail)[:120], flush=True)

def project():
    d = Path(tempfile.mkdtemp(prefix="vep-e2e-")); (d / "tests").mkdir()
    (d / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (d / "tests/test_calc.py").write_text("import unittest\nfrom calc import add\n\nclass T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n")
    KeyStore(Workspace.init(d)).ensure()
    return d

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]

async def mcp_flow():
    d = project()
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    ro = StdioServerParameters(command=str(BIN / "vep-mcp"), args=["--root", str(d), "--authority", "read"], env=env)
    async with Client(ro) as c:
        rec("mcp: protocol negotiated", c.protocol_version, c.protocol_version)
        tools = {t.name: t for t in (await c.list_tools()).tools}
        rec("mcp: 12 tools with output schemas", len(tools) == 12 and all(t.output_schema for t in tools.values()), len(tools))
        r = await c.call_tool("vep_objective_create", {"title": "x"})
        rec("mcp: write rejected without authority", r.is_error and r.structured_content["error"]["code"] == "VEP_E_NOT_AUTHORIZED")
    full = StdioServerParameters(command=str(BIN / "vep-mcp"), args=["--root", str(d), "--authority", "read,register,evaluate,export", "--trusted-local-execution"], env=env)
    async with Client(full) as c:
        o = (await c.call_tool("vep_objective_create", {"title": "add feature", "idempotency_key": "k1"})).structured_content
        (d / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
        cand = (await c.call_tool("vep_candidate_register", {"objective_id": o["objective_id"], "author": "e2e"})).structured_content
        rec("mcp: candidate registered, not certified by registration", cand["status"] in ("PROPOSED", "POLICY_CHECKED"), cand["status"])
        await c.call_tool("vep_evaluate", {"candidate_id": cand["candidate_id"]})
        for _ in range(240):
            js = (await c.call_tool("vep_job_status", {"candidate_id": cand["candidate_id"]})).structured_content
            if js["state"] in ("SUCCEEDED", "FAILED", "CANCELLED"): break
            await asyncio.sleep(0.5)
        res = js.get("result", {})
        rec("mcp: protected evaluation certified", res.get("candidate_status") == "CERTIFIED", res)
        cert = res["certificate_id"]
        v = (await c.call_tool("vep_verify_certificate", {"certificate_id": cert, "check_current_source": True})).structured_content
        rec("mcp: workspace verification valid", v["valid"] and v["assurance"] == "WORKSPACE_KEY_REGISTRY")
        exp = (await c.call_tool("vep_export_evidence", {"certificate_id": cert})).structured_content
        bundle = json.loads((d / exp["path"]).read_text())
        ws = Workspace(d)
        with ws.db.read() as cx:
            raw = bytes.fromhex(cx.execute("SELECT public_key_hex FROM trusted_keys").fetchone()["public_key_hex"])
        snap = (await c.call_tool("vep_candidate_state", {"candidate_id": cand["candidate_id"]})).structured_content["snapshot_id"]
        pol = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=snap)
        py = trustpolicy.verify_authorized(bundle, pol, "2099-01-01T00:00:00Z")
        rec("verify: authorized under external trust policy (Python)", py["valid"] and py["assurance"] == "AUTHORIZED")
        node = shutil.which("node")
        if node:
            (d / "p.json").write_text(json.dumps(pol))
            repo = os.environ["VEP_REPO"]
            out = json.loads(subprocess.run([node, repo + "/conformance/node/verify.mjs", "authorized", str(d / exp["path"]), str(d / "p.json"), "2099-01-01T00:00:00Z"], capture_output=True, text=True).stdout)
            rec("verify: authorized under external trust policy (Node)", out["valid"] and out["assurance"] == "AUTHORIZED")
        else:
            rec("verify: Node", False, "node not installed: NOT RUN")
        wrong = trustpolicy.make_policy("rp", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id="snap-" + "0" * 64)
        rec("verify: wrong expected snapshot rejected", trustpolicy.verify_authorized(bundle, wrong, "2099-01-01T00:00:00Z")["code"] == "SNAPSHOT_MISMATCH")
        (d / "feature.py").write_text("def twice(x):\n    return 3 * x\n")
        v2 = (await c.call_tool("vep_verify_certificate", {"certificate_id": cert, "check_current_source": True})).structured_content
        rec("verify: source mutation invalidates the exact snapshot", v2["valid"] is False and "SOURCE_CHANGED" in v2.get("reason", ""), v2.get("reason", "")[:80])
        r = await c.call_tool("vep_read_artifact", {"digest": "0" * 64})
        rec("mcp: unknown artifact handle rejected", r.is_error)
    return d

async def a2a_flow():
    d = project()
    (d / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
    port, token = free_port(), "t" * 32
    from vep import services
    admin = services.Context(root=d, authority=frozenset(services.AUTHORITIES), trusted_local_execution=True)
    obj = services.objective_create(admin, "t", "", "1.00")["objective_id"]
    (d / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
    def start():
        p = subprocess.Popen([str(BIN / "vep-a2a"), "--root", str(d), "--authority", "read,register,evaluate", "--trusted-local-execution", "--port", str(port)], env=dict(os.environ, VEP_A2A_TOKEN=token), stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json", timeout=1).status_code == 200: return p
            except httpx.HTTPError: time.sleep(0.1)
        raise RuntimeError("a2a did not start")
    async def client():
        h = httpx.AsyncClient(headers={"Authorization": f"Bearer {token}", "A2A-Version": "1.0"}, timeout=120)
        return h, await create_client(f"http://127.0.0.1:{port}", ClientConfig(httpx_client=h, streaming=True))
    p = start()
    mid = str(uuid.uuid4())
    def msg(payload, mid):
        m = new_data_message(payload, media_type="application/json", role=pb.ROLE_USER); m.message_id = mid; return m
    h, c = await client()
    task_id, state = None, None
    async for resp in c.send_message(pb.SendMessageRequest(message=msg({"skill": "vep.verify_change", "objective_id": obj}, mid))):
        if resp.HasField("task"): task_id, state = resp.task.id, resp.task.status.state
        elif resp.HasField("status_update"): state = resp.status_update.status.state
    rec("a2a: verify_change completes only when certified", state == pb.TASK_STATE_COMPLETED, state)
    t = await c.get_task(pb.GetTaskRequest(id=task_id))
    art = get_data_parts(t.artifacts[0].parts)[0]
    rec("a2a: artifact carries certificate id", art["candidate_status"] == "CERTIFIED", art["certificate_id"][:20])
    await c.close(); await h.aclose()
    # restart: the adapter's task state is in memory; the VEP job and candidate are durable
    p.kill(); p.wait(); p.stderr.close()
    p = start()
    h, c = await client()
    try:
        await c.get_task(pb.GetTaskRequest(id=task_id)); gone = False
    except Exception:
        gone = True
    rec("a2a: after restart the A2A task id is unknown (in-memory adapter state)", gone)
    with Workspace(d).db.read() as cx:
        jobs = cx.execute("SELECT state FROM jobs").fetchall(); cands = cx.execute("SELECT status FROM candidates").fetchall()
    rec("a2a: after restart the VEP job and certified candidate persist", [j["state"] for j in jobs] == ["SUCCEEDED"] and [x["status"] for x in cands] == ["CERTIFIED"])
    state2 = None
    async for resp in c.send_message(pb.SendMessageRequest(message=msg({"skill": "vep.verify_change", "objective_id": obj}, mid))):
        if resp.HasField("status_update"): state2 = resp.status_update.status.state
        elif resp.HasField("task"): state2 = resp.task.status.state
    with Workspace(d).db.read() as cx:
        n = cx.execute("SELECT COUNT(*) n FROM candidates").fetchone()["n"]
    rec("a2a: retrying the same message id after restart creates no second candidate", n == 1 and state2 == pb.TASK_STATE_COMPLETED, f"candidates={n}")
    r = httpx.post(f"http://127.0.0.1:{port}/a2a", json={}, timeout=10)
    rec("a2a: unauthenticated call rejected", r.status_code == 401)
    await c.close(); await h.aclose(); p.kill(); p.wait(); p.stderr.close()

async def main():
    await mcp_flow(); await a2a_flow()
    ok = all(s["ok"] for s in steps)
    print(json.dumps({"ok": ok, "package": versions.PACKAGE_VERSION, "installed_from_site_packages": "site-packages" in str(Path(vep.__file__)) and "/src/" not in str(Path(vep.__file__)), "steps": steps}))
asyncio.run(main())
'''


def run(*argv: str, cwd=None, timeout=1800) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), cwd=cwd, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--wheel")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        wheel = Path(a.wheel) if a.wheel else None
        if wheel is None:
            b = run(sys.executable, "-m", "build", "--wheel", "--outdir", str(t / "dist"), cwd=ROOT)
            if b.returncode:
                print(b.stderr[-500:]); return 1
            wheel = next((t / "dist").glob("*.whl"))
        run(sys.executable, "-m", "venv", str(t / "v"))
        inst = run(str(t / "v/bin/pip"), "install", "-q", f"{wheel}[mcp,a2a]")
        if inst.returncode:
            print("INSTALL FAILED", inst.stderr[-400:]); return 1
        drv = t / "driver.py"
        drv.write_text(DRIVER)
        import os
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
        env["VEP_REPO"] = str(ROOT)
        r = subprocess.run([str(t / "v/bin/python"), "-I", str(drv)], capture_output=True, text=True, env=env, cwd=t, timeout=1800)
        sys.stdout.write(r.stdout[-3000:])
        last = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
        if r.returncode or not last:
            print(r.stderr[-1500:]); return 1
        doc = json.loads(last[-1])
        doc["wheel"] = wheel.name
        import hashlib
        doc["wheel_sha256"] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        Path(a.out).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        return 0 if doc["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
