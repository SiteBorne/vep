"""Build actions: content-addressed local execution with a validated result cache.

An action id covers everything that may influence the result: the argv, the input snapshot, the toolchain
identity (interpreter path + digest + version), the allowed environment, the output list and the cache
policy. A cache entry is reused only when its stored result re-verifies (result blob and every output blob
re-hash correctly). On a miss the command runs; with `verify_determinism` it runs a second time and the
action is cached only if both runs produced identical outputs.

Not a sandbox: commands run as the invoking user (trusted-local). Remote execution (REAPI) is NOT implemented.
"""
from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonical_bytes, sha256_hex, strict_loads
from .errors import AuthorizationError, ExecutionError
from .snapshots import make_writable, materialize, validate_rel_path
from .workspace import Workspace, utcnow

BUILD_ACTION_VERSION = 1
CACHE_POLICIES = ("deterministic", "none")
SAFE_ENV_KEYS = {"PYTHONHASHSEED", "LANG", "PYTHONDONTWRITEBYTECODE", "SOURCE_DATE_EPOCH"}


@dataclass(frozen=True)
class BuildAction:
    argv: tuple[str, ...]                     # argv[0] may be "{python}" (the current interpreter)
    input_snapshot_id: str
    outputs: tuple[str, ...] = ()             # relative paths that must exist after a successful run
    env: tuple[tuple[str, str], ...] = ()     # extra env, restricted to SAFE_ENV_KEYS
    timeout_s: int = 300
    cache_policy: str = "deterministic"
    verify_determinism: bool = True

    def validate(self) -> None:
        if self.cache_policy not in CACHE_POLICIES:
            raise ExecutionError(f"cache_policy must be one of {CACHE_POLICIES}")
        if not self.argv or any(not isinstance(a, str) or "\0" in a for a in self.argv):
            raise ExecutionError("argv must be a non-empty list of NUL-free strings")
        exe = self.argv[0]
        if exe != "{python}" and not os.path.isabs(exe):
            raise AuthorizationError("argv[0] must be an absolute path or {python}")
        for k, _ in self.env:
            if k not in SAFE_ENV_KEYS:
                raise AuthorizationError(f"environment variable {k!r} is not permitted")
        for o in self.outputs:
            validate_rel_path(o)


def toolchain_identity(action: BuildAction) -> dict:
    py = action.argv[0] == "{python}"
    real = os.path.realpath(sys.executable if py else action.argv[0])
    return {"executable": real, "sha256": sha256_hex(Path(real).read_bytes()),
            "python": sys.version.split()[0] if py else None, "platform": sys.platform}


def action_id(action: BuildAction) -> str:
    action.validate()
    body = {"v": BUILD_ACTION_VERSION, "argv": list(action.argv), "input": action.input_snapshot_id,
            "toolchain": toolchain_identity(action), "env": sorted(action.env), "outputs": sorted(action.outputs),
            "cache_policy": action.cache_policy}
    return "bact-" + sha256_hex(b"vep.BuildAction.v1\0" + canonical_bytes(body))


def _run_once(ws: Workspace, action: BuildAction, snap) -> dict:
    scratch = Path(tempfile.mkdtemp(prefix="vep-build-"))
    try:
        work = scratch / "src"
        materialize(ws, snap, work, readonly=False)
        (scratch / "home").mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"), "TMPDIR": str(scratch),
               "PYTHONHASHSEED": "0", "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8", **dict(action.env)}
        argv = [sys.executable if (a == "{python}" and i == 0) else a for i, a in enumerate(action.argv)]
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        t0 = time.monotonic()
        timed_out = False
        with open(scratch / "o", "wb") as fo, open(scratch / "e", "wb") as fe:
            p = subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                                 start_new_session=True)
            try:
                rc = p.wait(timeout=action.timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                rc = p.wait()
        wall = time.monotonic() - t0
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
        outputs, missing = {}, []
        for o in action.outputs:
            f = work / o
            if f.is_file() and not f.is_symlink():
                outputs[o] = ws.cas.put(f.read_bytes())
            else:
                missing.append(o)
        return {"exit_code": rc, "timed_out": timed_out, "missing_outputs": missing, "outputs": outputs,
                "stdout": ws.cas.put((scratch / "o").read_bytes()[:2_000_000]),
                "stderr": ws.cas.put((scratch / "e").read_bytes()[:2_000_000]),
                "wall_us": int(wall * 1e6), "cpu_us": int(cpu * 1e6)}
    finally:
        make_writable(scratch)
        shutil.rmtree(scratch, ignore_errors=True)


def _same(a: dict, b: dict) -> bool:
    return all(a[k] == b[k] for k in ("exit_code", "outputs", "stdout", "stderr"))


def _log(ws: Workspace, aid: str, outcome: str, wall: float, cpu: float) -> None:
    with ws.db.tx() as c:
        c.execute("INSERT INTO build_log(action_id,outcome,wall_s,cpu_s,at) VALUES(?,?,?,?,?)",
                  (aid, outcome, wall, cpu, utcnow()))


def lookup(ws: Workspace, aid: str) -> dict | None:
    """Return a verified cached result, or None (absent, corrupt, mismatched or failed entries are misses)."""
    with ws.db.read() as c:
        row = c.execute("SELECT result_digest FROM build_cache WHERE action_id=?", (aid,)).fetchone()
    if row is None:
        return None
    try:
        res = strict_loads(ws.cas.get(row["result_digest"]))
        if res.get("action_id") != aid or res["exit_code"] != 0:
            return None
        if not all(ws.cas.verify(d) for d in [*res["outputs"].values(), res["stdout"], res["stderr"]]):
            return None
        return res
    except Exception:  # noqa: BLE001 - any corruption is a miss, never a reuse
        return None


def run(ws: Workspace, action: BuildAction, *, use_cache: bool = True) -> dict:
    snap = ws.get_object(action.input_snapshot_id, "Snapshot")
    aid = action_id(action)
    cacheable = action.cache_policy == "deterministic"
    if use_cache and cacheable:
        hit = lookup(ws, aid)
        if hit:
            _log(ws, aid, "HIT", 0.0, 0.0)
            return {**hit, "cache": "HIT", "failure": None, "executed_wall_s": 0.0, "saved_wall_s": hit["wall_us"] / 1e6,
                    "determinism_verified": True}
    r = _run_once(ws, action, snap)
    reason = "TIMEOUT" if r["timed_out"] else "NONZERO_EXIT" if r["exit_code"] != 0 \
        else "MISSING_OUTPUTS" if r["missing_outputs"] else None
    res = {"action_id": aid, **{k: r[k] for k in ("exit_code", "outputs", "stdout", "stderr", "wall_us", "cpu_us")}}
    cache = "UNCACHEABLE" if not cacheable else "MISS"
    executed, cpu = r["wall_us"] / 1e6, r["cpu_us"] / 1e6
    verified = False
    if reason is None and cacheable:
        if action.verify_determinism:
            r2 = _run_once(ws, action, snap)
            executed, cpu = executed + r2["wall_us"] / 1e6, cpu + r2["cpu_us"] / 1e6
            if _same(r, r2):
                verified = True
            else:
                reason, cache = "NONDETERMINISTIC", "NOT_CACHED"
        if reason is None:
            digest = ws.cas.put(canonical_bytes(res))
            with ws.db.tx() as c:
                c.execute("INSERT OR REPLACE INTO build_cache(action_id,result_digest,created_at) VALUES(?,?,?)",
                          (aid, digest, utcnow()))
    _log(ws, aid, reason or cache, executed, cpu)
    return {**res, "cache": cache, "failure": reason, "executed_wall_s": round(executed, 6), "saved_wall_s": 0.0,
            "determinism_verified": verified}


def stats(ws: Workspace) -> dict:
    with ws.db.read() as c:
        rows = c.execute("SELECT outcome, COUNT(*) n, SUM(wall_s) w, SUM(cpu_s) cpu FROM build_log GROUP BY outcome").fetchall()
    return {r["outcome"]: {"count": r["n"], "wall_s": round(r["w"], 6), "cpu_s": round(r["cpu"], 6)} for r in rows}
