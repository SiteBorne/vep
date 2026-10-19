"""Read-only Git inspection. Argument arrays only; no commit/push/merge/checkout is ever issued."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .errors import VepError
from .workspace import Workspace, utcnow

ALLOWED = {"rev-parse", "status", "diff"}
HEX_RE = re.compile(r"^[0-9a-f]{7,64}$")


def _git(path: Path, *args: str) -> subprocess.CompletedProcess:
    if args[0] not in ALLOWED:
        raise VepError(f"git subcommand {args[0]!r} is not permitted (read-only adapter)")
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"}
    return subprocess.run(["git", "-C", str(path), "-c", "core.fsmonitor=false", *args], capture_output=True,
                          env=env, check=False, timeout=30, stdin=subprocess.DEVNULL)


def is_repo(path: Path) -> bool:
    try:
        r = _git(path, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() == b"true"


def head(path: Path) -> str | None:
    r = _git(path, "rev-parse", "--verify", "-q", "HEAD")
    return r.stdout.decode().strip() if r.returncode == 0 else None


def status(path: Path) -> list[dict]:
    r = _git(path, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if r.returncode != 0:
        raise VepError("git status failed")
    out = []
    parts = r.stdout.split(b"\0")
    i = 0
    while i < len(parts):
        e = parts[i]
        if len(e) >= 4:
            code, name = e[:2].decode(), e[3:].decode("utf-8", "replace")
            if code[0] in "RC":
                i += 1  # skip original-path field
            out.append({"code": code, "path": name})
        i += 1
    return out


def changed_files(path: Path, base_commit: str) -> list[str]:
    if not HEX_RE.match(base_commit):
        raise VepError("base commit must be a hex object id")
    r = _git(path, "diff", "--name-only", "-z", base_commit, "HEAD", "--")
    if r.returncode != 0:
        raise VepError("git diff failed")
    return sorted(p.decode("utf-8", "replace") for p in r.stdout.split(b"\0") if p)


def inspect(path: Path) -> dict:
    if not is_repo(path):
        return {"is_repo": False}
    st = status(path)
    return {"is_repo": True, "head": head(path), "dirty": bool(st), "status": st}


def associate(ws: Workspace, snapshot_id: str, path: Path | None = None) -> dict:
    """Record (commit, dirty) <-> snapshot. A dirty tree is recorded as dirty: the commit alone does not
    identify the snapshot content."""
    info = inspect(path or ws.root)
    if not info["is_repo"] or not info["head"]:
        raise VepError("not a git repository with a commit")
    with ws.db.tx() as c:
        c.execute("INSERT OR IGNORE INTO git_links(snapshot_id,commit_id,dirty,at) VALUES(?,?,?,?)",
                  (snapshot_id, info["head"], int(info["dirty"]), utcnow()))
    return {"snapshot_id": snapshot_id, "commit": info["head"], "dirty": info["dirty"]}
