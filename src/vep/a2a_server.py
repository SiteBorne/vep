"""VEP A2A 1.0 adapter (JSON-RPC over HTTP) on the official a2a-sdk. Thin: all domain work goes through `vep.services`.

    VEP_A2A_TOKEN=... vep-a2a --root PROJECT --authority read,register --port 8421 [--trusted-local-execution]

Mapping. One A2A task <-> one VEP request. Skills (a DataPart `{"skill": ..., ...}` in the user message):
  vep.verify_change   {objective_id}   registers the working tree as a candidate, queues the protected evaluation, follows the job.
                                       COMPLETED only if VEP certified the candidate; REJECTED/failed evaluations are FAILED; cancel cancels the job.
  vep.get_status      {}               workspace status.
  vep.explain_failure {candidate_id}   failed invariant and remedy.
Authority is fixed by the operator at start-up, exactly as for the MCP server; a remote caller can never supply a verdict. The A2A message id is
the idempotency key: a duplicate message re-uses the VEP candidate and job instead of creating another. Bearer-token authentication is required
for every JSON-RPC call (the Agent Card is public). The server binds to loopback unless told otherwise; TLS and rate limiting belong to the
reverse proxy in front of it. Remote write access is NOT qualified (docs/A2A.md).
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from a2a.helpers.proto_helpers import get_data_parts, new_data_artifact, new_data_message, new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types import a2a_pb2 as pb
from starlette.applications import Starlette
from starlette.responses import JSONResponse

from . import services, versions
from .services import AUTHORITIES, Context, ServiceError

RPC_PATH = "/a2a"
SKILLS = {
    "vep.verify_change": ("Verify a change", "Register the current working tree against an objective and run the protected evaluation.", ("register", "evaluate")),
    "vep.get_status": ("Workspace status", "Versions, counts, enabled authority and the next action.", ("read",)),
    "vep.explain_failure": ("Explain a failure", "Which invariant failed, why, and the remedy.", ("read",)),
}
PRE_TERMINAL = {"QUEUED", "RUNNING", "PENDING", "LEASED"}
REJECT_CODES = {"VEP_E_INVALID_ARGUMENT", "VEP_E_NOT_AUTHORIZED", "VEP_E_EVALUATION_DISABLED", "VEP_E_NOT_FOUND"}


def idem_key(message_id: str) -> str:
    return "a2a-" + hashlib.sha256(message_id.encode()).hexdigest()[:40]


def _map_put(ws, task_id: str, value: dict) -> None:
    with ws.db.tx() as c:
        c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (f"a2a:task:{task_id}", json.dumps(value, sort_keys=True)))


def _map_get(ws, task_id: str) -> dict | None:
    with ws.db.read() as c:
        row = c.execute("SELECT value FROM meta WHERE key=?", (f"a2a:task:{task_id}",)).fetchone()
    return json.loads(row["value"]) if row else None


class VepExecutor(AgentExecutor):
    def __init__(self, ctx: Context, *, task_timeout: float = 600.0, poll: float = 0.5):
        self.ctx, self.task_timeout, self.poll = ctx, task_timeout, poll

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _parse(context: RequestContext) -> tuple[str, dict]:
        msg = context.message
        if msg is None:
            raise ServiceError("VEP_E_INVALID_ARGUMENT", "no message")
        data = [d for d in get_data_parts(msg.parts) if isinstance(d, dict)]
        if len(data) != 1:
            raise ServiceError("VEP_E_INVALID_ARGUMENT", 'send exactly one data part: {"skill": "vep.verify_change", "objective_id": "obj-..."}',
                               skills=sorted(SKILLS))
        args = dict(data[0])
        skill = args.pop("skill", None)
        if skill not in SKILLS:
            raise ServiceError("VEP_E_INVALID_ARGUMENT", f"unknown skill {skill!r}", skills=sorted(SKILLS))
        return skill, args

    async def _call(self, fn, *a, **kw):
        return await asyncio.to_thread(fn, self.ctx, *a, **kw)

    async def _finish_error(self, up: TaskUpdater, e: ServiceError) -> None:
        msg = new_data_message(e.to_dict(), media_type="application/json", context_id=up.context_id, task_id=up.task_id)
        await (up.reject(msg) if e.code in REJECT_CODES else up.failed(msg))

    # ------------------------------------------------------------ AgentExecutor
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id, context_id = context.task_id, context.context_id
        if context.current_task is None:
            await event_queue.enqueue_event(pb.Task(id=task_id, context_id=context_id, status=pb.TaskStatus(state=pb.TASK_STATE_SUBMITTED),
                                                    history=[context.message] if context.message else []))
        up = TaskUpdater(event_queue, task_id, context_id)
        try:
            skill, args = self._parse(context)
            if skill == "vep.verify_change":
                await self._verify_change(up, context, args)
            elif skill == "vep.get_status":
                await self._artifact_done(up, "status", await self._call(services.status))
            else:
                await self._artifact_done(up, "failure-explanation", await self._call(services.explain_failure, args.get("candidate_id"), args.get("job_id")))
        except ServiceError as e:
            await self._finish_error(up, e)

    async def _artifact_done(self, up: TaskUpdater, name: str, data: dict) -> None:
        art = new_data_artifact(name, data, media_type="application/json")
        await up.add_artifact(list(art.parts), name=name, last_chunk=True)
        await up.complete()

    async def _verify_change(self, up: TaskUpdater, context: RequestContext, args: dict) -> None:
        extra = set(args) - {"objective_id", "author"}
        if extra:
            raise ServiceError("VEP_E_INVALID_ARGUMENT", f"unexpected arguments {sorted(extra)}; a caller cannot supply verdicts, trust levels or authority")
        key = idem_key(context.message.message_id)
        reg = await self._call(services.candidate_register, args.get("objective_id"), args.get("author") or "a2a-client", key)
        cand = reg["candidate_id"]
        if reg["policy_violations"]:
            failure = await self._call(services.explain_failure, cand)
            await self._artifact_failed(up, failure, "candidate violates the frozen policy before evaluation")
            return
        job = await self._call(services.evaluate, cand)
        ws = self.ctx.ws()
        await asyncio.to_thread(_map_put, ws, up.task_id, {"candidate_id": cand, "job_id": job["job_id"], "message_key": key})
        await up.start_work(new_data_message({"candidate_id": cand, "job_id": job["job_id"], "idempotent_replay": bool(reg.get("idempotent_replay"))},
                                             media_type="application/json", context_id=up.context_id, task_id=up.task_id))
        deadline = time.monotonic() + self.task_timeout
        while True:
            st = await self._call(services.job_status, job["job_id"])
            if st["state"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            if time.monotonic() > deadline:
                await self._call(services.cancel_job, job["job_id"])
                await up.failed(new_data_message({"ok": False, "error": {"code": "VEP_E_STATE", "message": "task deadline exceeded; the VEP job was cancelled"}},
                                                 media_type="application/json", context_id=up.context_id, task_id=up.task_id))
                return
            await asyncio.sleep(self.poll)
        result = st.get("result") or {}
        if st["state"] == "SUCCEEDED" and result.get("candidate_status") == "CERTIFIED":
            await self._artifact_done(up, "verification", {"ok": True, **{k: result.get(k) for k in ("candidate_status", "trust_level", "evidence_id", "certificate_id")},
                                                              "candidate_id": cand, "job_id": job["job_id"],
                                                              "assurance": "verified against this workspace's own keys; export a v2 bundle for a relying party"})
        elif st["state"] == "CANCELLED":
            await up.cancel()
        else:
            await self._artifact_failed(up, await self._call(services.explain_failure, cand), "evaluation did not certify the candidate")

    async def _artifact_failed(self, up: TaskUpdater, data: dict, text: str) -> None:
        art = new_data_artifact("failure-explanation", data, media_type="application/json")
        await up.add_artifact(list(art.parts), name="failure-explanation", last_chunk=True)
        await up.failed(new_text_message(text, context_id=up.context_id, task_id=up.task_id))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        up = TaskUpdater(event_queue, context.task_id, context.context_id)
        m = await asyncio.to_thread(_map_get, self.ctx.ws(), context.task_id)
        if m and m.get("job_id"):
            try:
                await self._call(services.cancel_job, m["job_id"])
            except ServiceError:
                pass
        await up.cancel()


# ------------------------------------------------------------------ auth
class BearerAuth:
    """ASGI middleware: JSON-RPC requires `Authorization: Bearer <token>`; the Agent Card stays public. Optional token expiry (epoch seconds)."""

    def __init__(self, app, token: str, expires_at: float | None = None):
        self.app, self.token, self.expires_at = app, token.encode(), expires_at

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == RPC_PATH:
            h = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            auth = h.get("authorization", "")
            ok = auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].encode(), self.token)
            expired = self.expires_at is not None and time.time() >= self.expires_at
            if not ok or expired:
                body = {"error": {"code": "UNAUTHENTICATED", "message": "token expired" if ok and expired else "missing or invalid bearer token"}}
                await JSONResponse(body, status_code=401, headers={"WWW-Authenticate": "Bearer"})(scope, receive, send)
                return
        await self.app(scope, receive, send)


def build_card(ctx: Context, base_url: str) -> pb.AgentCard:
    skills = [pb.AgentSkill(id=k, name=n, description=d + f" Needs authority: {', '.join(a)}.", tags=["verification", "vep"],
                            input_modes=["application/json"], output_modes=["application/json"]) for k, (n, d, a) in SKILLS.items()]
    return pb.AgentCard(
        name="VEP", description="Verified Evolution Protocol: protected, evidence-carrying verification of code changes. Remote write access is operator-gated.",
        version=versions.PACKAGE_VERSION, provider=pb.AgentProvider(organization="VEP", url="https://github.com/SiteBorne/vep"),
        supported_interfaces=[pb.AgentInterface(url=base_url.rstrip("/") + RPC_PATH, protocol_binding="JSONRPC", protocol_version="1.0")],
        capabilities=pb.AgentCapabilities(streaming=True, push_notifications=False, extended_agent_card=False),
        default_input_modes=["application/json"], default_output_modes=["application/json"], skills=skills,
        security_schemes={"bearer": pb.SecurityScheme(http_auth_security_scheme=pb.HTTPAuthSecurityScheme(scheme="Bearer", description="operator-issued static token"))},
        security_requirements=[pb.SecurityRequirement(schemes={"bearer": pb.StringList(list=[])})])


def build_app(ctx: Context, token: str, *, base_url: str = "http://127.0.0.1:8421", task_timeout: float = 600.0, poll: float = 0.5,
              token_expires_at: float | None = None) -> Starlette:
    if not token or len(token) < 16:
        raise ValueError("a bearer token of at least 16 characters is required")
    card = build_card(ctx, base_url)
    handler = DefaultRequestHandler(agent_executor=VepExecutor(ctx, task_timeout=task_timeout, poll=poll), task_store=InMemoryTaskStore(), agent_card=card)
    routes = create_agent_card_routes(card) + create_jsonrpc_routes(handler, RPC_PATH)
    app = Starlette(routes=routes)
    return BearerAuth(app, token, token_expires_at)  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    import os
    import uvicorn
    ap = argparse.ArgumentParser(prog="vep-a2a", description=__doc__.split("\n")[0])
    ap.add_argument("--root", default="."); ap.add_argument("--authority", default="read")
    ap.add_argument("--trusted-local-execution", action="store_true")
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8421)
    ap.add_argument("--public-url", help="URL clients use to reach this server (default http://HOST:PORT)")
    ap.add_argument("--task-timeout", type=float, default=600.0)
    ap.add_argument("--token-expires", help="ISO-8601 time after which the token is refused")
    ap.add_argument("--allow-nonlocal", action="store_true", help="bind a non-loopback address (put TLS in front; see docs/A2A.md)")
    a = ap.parse_args(argv)
    token = os.environ.get("VEP_A2A_TOKEN", "")
    if len(token) < 16:
        print("vep-a2a: set VEP_A2A_TOKEN (>= 16 characters); unauthenticated serving is not offered", file=sys.stderr)
        return 2
    if a.host not in ("127.0.0.1", "::1", "localhost") and not a.allow_nonlocal:
        print("vep-a2a: refusing a non-loopback bind without --allow-nonlocal", file=sys.stderr)
        return 2
    granted = frozenset(x.strip() for x in a.authority.split(",") if x.strip())
    if not granted <= set(AUTHORITIES):
        print(f"vep-a2a: unknown authority {sorted(granted - set(AUTHORITIES))}", file=sys.stderr)
        return 2
    exp = datetime.fromisoformat(a.token_expires.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() if a.token_expires else None
    ctx = Context(root=Path(a.root).resolve(), authority=granted, trusted_local_execution=a.trusted_local_execution, actor="vep-a2a")
    app = build_app(ctx, token, base_url=a.public_url or f"http://{a.host}:{a.port}", task_timeout=a.task_timeout, token_expires_at=exp)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
