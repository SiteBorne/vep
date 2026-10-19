"""Agent interoperability: a versioned adapter interface and two concrete adapters.

An adapter produces a *candidate snapshot* and a usage record. It never evaluates, never certifies, and
never touches VEP state: `run_agent_task` registers the produced snapshot as an ordinary Candidate that must
still pass the frozen policy, the protected evaluator and certification.

Usage provenance (never upgraded silently):
  provider_reported  - counted by the model runtime's own API response
  locally_measured   - measured by VEP around the child process (wall time, CPU time)
  caller_supplied    - claimed by the tool/agent itself; unauthenticated
  estimated / simulated / none
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from . import candidates
from .canonical import sha256_hex
from .errors import AuthorizationError, ExecutionError, VepError
from .snapshots import diff, make_writable, materialize, take_snapshot, validate_rel_path
from .workspace import Workspace

ADAPTER_INTERFACE_VERSION = 1
USAGE_SOURCES = ("provider_reported", "locally_measured", "caller_supplied", "estimated", "simulated", "none")
ERROR_CLASSES = ("NONE", "TIMEOUT", "NONZERO_EXIT", "NOT_ALLOWED", "BAD_OUTPUT", "RUNTIME_UNAVAILABLE", "CANCELLED")
MAX_ARG_LEN = 4096


@dataclass
class AgentTask:
    objective_id: str
    base_snapshot_id: str
    policy_id: str
    instruction: str
    params: dict[str, str] = field(default_factory=dict)
    timeout_s: int = 120


@dataclass
class Prepared:
    task: AgentTask
    workdir: Path
    scratch: Path


class AgentAdapter(Protocol):
    interface_version: int
    name: str

    def capabilities(self) -> dict: ...
    def prepare_task(self, ws: Workspace, task: AgentTask) -> Prepared: ...
    def execute_task(self, ws: Workspace, prepared: Prepared) -> dict: ...
    def collect_result(self, ws: Workspace, prepared: Prepared, raw: dict) -> dict: ...
    def collect_usage(self, raw: dict) -> dict: ...
    def cancel(self, prepared: Prepared) -> None: ...


def usage_record(source: str, **values: Any) -> dict:
    if source not in USAGE_SOURCES:
        raise VepError(f"unknown usage source {source!r}")
    return {"source": source, **values}


class _Base:
    interface_version = ADAPTER_INTERFACE_VERSION

    def __init__(self) -> None:
        self._procs: dict[str, subprocess.Popen] = {}

    def prepare_task(self, ws: Workspace, task: AgentTask) -> Prepared:
        ws.get_object(task.base_snapshot_id, "Snapshot")
        scratch = Path(tempfile.mkdtemp(prefix="vep-agent-"))
        for forbidden in (ws.root, ws.state):
            if scratch.resolve() == forbidden or forbidden in scratch.resolve().parents:
                raise ExecutionError("agent scratch lies inside the workspace; refusing")
        work = scratch / "work"
        materialize(ws, ws.get_object(task.base_snapshot_id, "Snapshot"), work, readonly=False)
        return Prepared(task, work, scratch)

    def cancel(self, prepared: Prepared) -> None:
        p = self._procs.get(str(prepared.scratch))
        if p and p.poll() is None:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def collect_result(self, ws: Workspace, prepared: Prepared, raw: dict) -> dict:
        base = ws.get_object(prepared.task.base_snapshot_id, "Snapshot")
        snap = take_snapshot(ws, prepared.workdir)
        changes = diff(base, snap)
        return {"adapter": self.name, "interface_version": self.interface_version,
                "input_snapshot_id": prepared.task.base_snapshot_id, "objective_id": prepared.task.objective_id,
                "policy_id": prepared.task.policy_id, "output_snapshot_id": snap.id, "changes": changes,
                "tool_invocations": raw.get("tool_invocations", []), "runtime": raw.get("runtime", {}),
                "status": raw["status"], "error_class": raw["error_class"], "duration_s": raw["duration_s"],
                "artifact_digests": {"stdout": raw.get("stdout_digest"), "stderr": raw.get("stderr_digest")},
                "usage": self.collect_usage(raw)}

    def cleanup(self, prepared: Prepared) -> None:
        make_writable(prepared.scratch)
        shutil.rmtree(prepared.scratch, ignore_errors=True)


class StructuredSubprocessAdapter(_Base):
    """Runs allowlisted executables with structured argv. No shell; model output is never executed.

    allowlist: {tool_name: {"executable": "/abs/path", "args": ["--flag", "{param:name}", "{workdir}"]}}
    The tool runs with cwd = a disposable copy of the base snapshot, a scrubbed environment and no stdin.
    It is NOT sandboxed: it can read anything the invoking user can, so only allowlist tools you trust.
    A tool may write `$VEP_USAGE_FILE` JSON ({"input_tokens":..,"output_tokens":..}); that is labelled
    caller_supplied because nothing authenticates it.
    """

    def __init__(self, name: str, allowlist: dict[str, dict], max_output_bytes: int = 1_000_000):
        super().__init__()
        self.name = name
        for tool, spec in allowlist.items():
            exe = spec.get("executable", "")
            if not os.path.isabs(exe) or not os.access(exe, os.X_OK):
                raise AuthorizationError(f"allowlist entry {tool!r}: executable must be an existing absolute path")
        self._allow, self._cap = allowlist, max_output_bytes

    def capabilities(self) -> dict:
        return {"interface_version": self.interface_version, "adapter": self.name, "tools": sorted(self._allow),
                "sandboxed": False, "usage_sources": ["locally_measured", "caller_supplied"],
                "network_policy": "not enforced"}

    def _argv(self, task: AgentTask, work: Path) -> list[str]:
        tool = task.params.get("tool")
        spec = self._allow.get(tool or "")
        if spec is None:
            raise AuthorizationError(f"NOT_ALLOWED: tool {tool!r} is not on the allowlist")
        argv = [spec["executable"]]
        for tpl in spec.get("args", []):
            if tpl == "{workdir}":
                argv.append(str(work))
            elif tpl.startswith("{param:") and tpl.endswith("}"):
                val = task.params.get(tpl[7:-1])
                if val is None or not isinstance(val, str) or "\0" in val or len(val) > MAX_ARG_LEN or val.startswith("-"):
                    raise AuthorizationError(f"NOT_ALLOWED: parameter {tpl} missing or unsafe")
                argv.append(val)
            elif "{" in tpl:
                raise AuthorizationError(f"NOT_ALLOWED: unsupported template {tpl!r}")
            else:
                argv.append(tpl)
        return argv

    def execute_task(self, ws: Workspace, prepared: Prepared) -> dict:
        task, scratch = prepared.task, prepared.scratch
        t0 = time.monotonic()
        try:
            argv = self._argv(task, prepared.workdir)
        except AuthorizationError as exc:
            return {"status": "FAILED", "error_class": "NOT_ALLOWED", "duration_s": 0.0, "detail": str(exc)}
        usage_file = scratch / "usage.json"
        (scratch / "home").mkdir(exist_ok=True)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"), "TMPDIR": str(scratch),
               "VEP_USAGE_FILE": str(usage_file), "LANG": "C.UTF-8"}
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        out_p, err_p = scratch / "stdout.txt", scratch / "stderr.txt"
        timed_out = False
        with open(out_p, "wb") as fo, open(err_p, "wb") as fe:
            proc = subprocess.Popen(argv, cwd=prepared.workdir, env=env, stdin=subprocess.DEVNULL, stdout=fo,
                                    stderr=fe, start_new_session=True)
            self._procs[str(scratch)] = proc
            try:
                rc = proc.wait(timeout=task.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                self.cancel(prepared)
                rc = proc.wait()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cancelled = rc in (-signal.SIGKILL,) and not timed_out
        out, err = out_p.read_bytes()[:self._cap], err_p.read_bytes()[:self._cap]
        cls = "TIMEOUT" if timed_out else "CANCELLED" if cancelled else "NONZERO_EXIT" if rc else "NONE"
        claimed = None
        if usage_file.is_file():
            try:
                claimed = json.loads(usage_file.read_bytes()[:10_000])
            except ValueError:
                claimed = None
        return {"status": "COMPLETED" if rc == 0 else "FAILED", "error_class": cls, "exit_code": rc,
                "duration_s": round(time.monotonic() - t0, 6),
                "cpu_s": round((after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), 6),
                "stdout_digest": ws.cas.put(out), "stderr_digest": ws.cas.put(err), "claimed_usage": claimed,
                "tool_invocations": [{"tool": task.params.get("tool"), "argv": argv}],
                "runtime": {"kind": "subprocess", "executable_sha256": sha256_hex(Path(argv[0]).read_bytes())}}

    def collect_usage(self, raw: dict) -> dict:
        u = usage_record("locally_measured", wall_s=raw["duration_s"], cpu_s=raw.get("cpu_s"))
        if isinstance(raw.get("claimed_usage"), dict):
            u["tool_claimed"] = usage_record("caller_supplied", **{
                k: v for k, v in raw["claimed_usage"].items() if isinstance(v, int) and not isinstance(v, bool) and v >= 0})
        return u


class OllamaAdapter(_Base):
    """Ollama-compatible local inference API (/api/chat). Token counts come from the runtime's own response.

    The model is asked for JSON `{"files": {"relative/path": "full new content"}}`. Paths are validated with the
    snapshot path rules and written only inside the task workdir; model text is never executed.
    """

    def __init__(self, model: str, base_url: str = "http://127.0.0.1:11434", name: str = "ollama"):
        super().__init__()
        self.name, self.model, self.base_url = name, model, base_url.rstrip("/")

    def capabilities(self) -> dict:
        return {"interface_version": self.interface_version, "adapter": self.name, "model": self.model,
                "sandboxed": False, "usage_sources": ["provider_reported", "locally_measured"]}

    def execute_task(self, ws: Workspace, prepared: Prepared) -> dict:
        task = prepared.task
        t0 = time.monotonic()
        listing = "\n".join(f"--- {p}\n{(prepared.workdir / p).read_text(errors='replace')[:6000]}"
                            for p in sorted(task.params.get("context_paths", "").split(",")) if p)
        body = {"model": self.model, "stream": False, "format": "json", "messages": [
            {"role": "system", "content": 'Reply with JSON only: {"files": {"<relative path>": "<full file content>"}}'},
            {"role": "user", "content": f"{task.instruction}\n\n{listing}"}]}
        req = urllib.request.Request(f"{self.base_url}/api/chat", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        base = {"duration_s": 0.0, "runtime": {"kind": "ollama", "model": self.model, "url": self.base_url}}
        try:
            with urllib.request.urlopen(req, timeout=task.timeout_s) as r:
                resp = json.loads(r.read(20_000_000))
        except (OSError, ValueError) as exc:
            return {**base, "status": "FAILED", "error_class": "RUNTIME_UNAVAILABLE", "detail": str(exc)[:300],
                    "duration_s": round(time.monotonic() - t0, 6)}
        raw = {**base, "duration_s": round(time.monotonic() - t0, 6), "provider_usage": {
            "input_tokens": resp.get("prompt_eval_count"), "output_tokens": resp.get("eval_count")},
            "tool_invocations": [{"tool": "ollama/api/chat", "model": self.model}]}
        try:
            files = json.loads(resp["message"]["content"])["files"]
            assert isinstance(files, dict) and files
            for rel, content in files.items():
                rel = validate_rel_path(rel)
                assert isinstance(content, str) and len(content) <= 1_000_000
                dest = prepared.workdir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content)
        except Exception as exc:  # noqa: BLE001 - any malformed model output is BAD_OUTPUT, never executed
            return {**raw, "status": "FAILED", "error_class": "BAD_OUTPUT", "detail": f"{exc.__class__.__name__}"}
        return {**raw, "status": "COMPLETED", "error_class": "NONE"}

    def collect_usage(self, raw: dict) -> dict:
        u = usage_record("locally_measured", wall_s=raw["duration_s"])
        pu = raw.get("provider_usage")
        if pu and all(isinstance(pu.get(k), int) for k in ("input_tokens", "output_tokens")):
            u["provider"] = usage_record("provider_reported", **pu)
        return u


def run_agent_task(ws: Workspace, adapter: AgentAdapter, task: AgentTask, author: str) -> dict:
    """Prepare, execute, collect; register the output as an UNCERTIFIED Candidate if it changed anything.

    The adapter's claims are recorded but grant nothing: the candidate must still be evaluated.
    """
    prepared = adapter.prepare_task(ws, task)
    try:
        raw = adapter.execute_task(ws, prepared)
        if "status" not in raw:
            raise ExecutionError("adapter returned no status")
        result = adapter.collect_result(ws, prepared, raw)
        result["detail"] = raw.get("detail")
        cand = None
        if result["status"] == "COMPLETED" and any(result["changes"].values()):
            cand = candidates.register_candidate(ws, task.objective_id, result["output_snapshot_id"], author,
                                                 base_snapshot_id=task.base_snapshot_id)
        result["candidate_id"] = cand.id if cand else None
        return result
    finally:
        adapter.cleanup(prepared)


ZERO_PRICES = {"input": "0", "cached_input": "0", "cache_write": "0", "output": "0"}


def record_usage(ws: Workspace, result: dict, *, attempt: int = 0, prices_per_million: dict | None = None,
                 pricing_version: str = "unpriced-local-runtime", reservation_key: str | None = None) -> dict | None:
    """Persist an adapter's token usage as a TokenReceipt, preserving provenance. Never fabricates usage.

    Runtime-reported figures become `provider_reported`; a tool's own claim becomes `caller_supplied`.
    Wall/CPU measurements are not tokens and are not receipted. Returns None when no token usage exists
    or the run produced no candidate to attach it to.
    """
    from . import tokens
    cid, usage = result.get("candidate_id"), result["usage"]
    if not cid:
        return None
    pick = None
    if "provider" in usage:
        pick, model = usage["provider"], result["runtime"].get("model", result["adapter"])
    elif "tool_claimed" in usage and {"input_tokens", "output_tokens"} <= usage["tool_claimed"].keys():
        pick, model = usage["tool_claimed"], result["adapter"]
    if pick is None:
        return None
    rc = tokens.make_receipt(
        provider=result["adapter"], model=str(model), pricing_version=pricing_version, candidate_id=cid, attempt=attempt,
        ordinary_input_tokens=pick["input_tokens"], cached_input_tokens=0, cache_write_tokens=0,
        output_tokens=pick["output_tokens"], reasoning_tokens_in_output=0,
        prices_per_million=prices_per_million or ZERO_PRICES, usage_source=pick["source"],
        idempotency_key=f"agent:{result['adapter']}:{result['input_snapshot_id']}:{result['output_snapshot_id']}:{attempt}")
    return tokens.record_receipt(ws, rc, reservation_key)
