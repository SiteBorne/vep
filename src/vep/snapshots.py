"""Deterministic source snapshots (manifest of path -> content digest)."""
from __future__ import annotations

import fnmatch
import os
import stat
import unicodedata
from pathlib import Path
from typing import Any

from .errors import SnapshotError
from .objects import VEPObject
from .workspace import Workspace

MANIFEST_VERSION = 1
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PATH_LEN = 1024

DEFAULT_EXCLUDES = (
    ".vep", ".git", ".hg", ".svn", "__pycache__", "*.pyc", ".venv", "venv", ".pytest_cache",
    ".mypy_cache", "*.egg-info", ".DS_Store", ".env", ".env.*", "*.pem", "*.key", "id_rsa*",
    "id_ed25519*", "*.p12",
)


def validate_rel_path(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise SnapshotError("path must be a non-empty string")
    if len(path) > MAX_PATH_LEN or "\\" in path or "\x00" in path or path.startswith("/"):
        raise SnapshotError(f"unsafe path {path!r}")
    if any(ord(ch) < 32 for ch in path):
        raise SnapshotError(f"control character in path {path!r}")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise SnapshotError(f"unsafe path {path!r}")
    return path


def _excluded(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def find_collisions(paths: list[str]) -> list[tuple[str, str]]:
    """Pairs of distinct paths that collide on case-insensitive / Unicode-normalizing filesystems."""
    seen: dict[str, str] = {}
    out = []
    for p in sorted(paths):
        fold = unicodedata.normalize("NFC", p).casefold()
        if fold in seen and seen[fold] != p:
            out.append((seen[fold], p))
        seen.setdefault(fold, p)
    return out


def scan_tree(root: Path, excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> dict[str, dict]:
    """Walk root; return {path: {digest-less info}}. Rejects symlinks and special files."""
    root = Path(root)
    found: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if _excluded(d, excludes):
                continue
            if os.path.islink(full):
                raise SnapshotError(f"symlink not permitted: {os.path.relpath(full, root)}")
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            if _excluded(f, excludes):
                continue
            full = os.path.join(dirpath, f)
            rel = f if rel_dir == "." else f"{rel_dir}/{f}".replace(os.sep, "/")
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise SnapshotError(f"symlink not permitted: {rel}")
            if not stat.S_ISREG(st.st_mode):
                raise SnapshotError(f"special file not permitted: {rel}")
            if st.st_size > MAX_FILE_BYTES:
                raise SnapshotError(f"file too large: {rel}")
            validate_rel_path(rel)
            found[rel] = {"executable": bool(st.st_mode & stat.S_IXUSR), "full": full}
    collisions = find_collisions(list(found))
    if collisions:
        raise SnapshotError(f"case/normalization collision: {collisions[0][0]} vs {collisions[0][1]}")
    return found


def read_regular_nofollow(path: str) -> bytes:
    """Read a regular file without following a symlink swapped in after the scan (TOCTOU)."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise SnapshotError(f"cannot open {path!r} safely: {exc.strerror}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise SnapshotError(f"not a regular file: {path!r}")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)


def build_entries(ws: Workspace | None, root: Path, excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
                  store: bool = True) -> list[dict]:
    import hashlib
    entries = []
    for rel, info in sorted(scan_tree(root, excludes).items()):
        data = read_regular_nofollow(info["full"])
        if len(data) > MAX_FILE_BYTES:
            raise SnapshotError(f"file too large: {rel}")
        digest = ws.cas.put(data) if (store and ws is not None) else hashlib.sha256(data).hexdigest()
        entries.append({"path": rel, "digest": digest, "type": "file", "executable": info["executable"]})
    return entries


def make_snapshot_object(entries: list[dict]) -> VEPObject:
    paths = [e["path"] for e in entries]
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        raise SnapshotError("entries must be unique and sorted")
    return VEPObject.create("Snapshot", {"manifest_version": MANIFEST_VERSION, "entries": entries})


def take_snapshot(ws: Workspace, root: Path | None = None) -> VEPObject:
    snap = make_snapshot_object(build_entries(ws, root or ws.root))
    ws.put_object(snap)
    return snap


def tree_snapshot_id(root: Path, excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> str:
    """Identity of a directory tree without storing anything (used for post-run checks)."""
    return make_snapshot_object(build_entries(None, root, excludes, store=False)).id


def entries_of(snap: VEPObject) -> dict[str, dict]:
    return {e["path"]: e for e in snap["entries"]}


def diff(a: VEPObject, b: VEPObject) -> dict[str, list[str]]:
    ea, eb = entries_of(a), entries_of(b)
    return {
        "added": sorted(set(eb) - set(ea)),
        "removed": sorted(set(ea) - set(eb)),
        "modified": sorted(p for p in set(ea) & set(eb) if ea[p]["digest"] != eb[p]["digest"]),
        "mode_changed": sorted(p for p in set(ea) & set(eb)
                               if ea[p]["digest"] == eb[p]["digest"] and ea[p]["executable"] != eb[p]["executable"]),
    }


def verify_snapshot(ws: Workspace, snap: VEPObject) -> None:
    """Every referenced blob must exist and match its digest."""
    for e in snap["entries"]:
        validate_rel_path(e["path"])
        if not ws.cas.verify(e["digest"]):
            raise SnapshotError(f"blob for {e['path']} missing or corrupt")


def materialize(ws: Workspace, snap: VEPObject, dest: Path, readonly: bool = True) -> None:
    """Write the exact snapshot into dest (a fresh directory outside the workspace)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise SnapshotError("staging directory must be empty")
    for e in snap["entries"]:
        rel = validate_rel_path(e["path"])
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(ws.cas.get(e["digest"]))
        mode = 0o755 if e["executable"] else 0o644
        os.chmod(target, mode & ~0o222 if readonly else mode)
    if readonly:
        for d in sorted((p for p in dest.rglob("*") if p.is_dir()), reverse=True):
            os.chmod(d, 0o555)
        os.chmod(dest, 0o555)


def make_writable(path: Path) -> None:
    for p in [path, *path.rglob("*")]:
        try:
            if not p.is_symlink():
                os.chmod(p, 0o755 if p.is_dir() else 0o644)
        except OSError:
            pass
