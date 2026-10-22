"""Install, inspect and remove the Claude Code integration for a project: `.mcp.json` entry, Skill, CLAUDE.md block, guard hook.

    vep claude install|status|uninstall|plugin

Every file this module writes is recorded (with its sha256) in `.claude/vep-install.json`. Existing user content is never overwritten
silently: a differing file or MCP entry is a conflict unless `force` is given, in which case it is copied to `.claude/vep-backups/<stamp>/`
first. Uninstall removes only what is still byte-identical to what was installed. The operator's authority (what the agent may do through
the MCP server) is fixed here, in `.mcp.json`; the agent cannot raise it.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from importlib import resources
from pathlib import Path

from .errors import VepError

SERVER = "vep"
MANIFEST = Path(".claude") / "vep-install.json"
BEGIN, END = "<!-- vep:begin (managed by `vep claude install`) -->", "<!-- vep:end -->"
GUARD_MARK = "vep_guard.py"
GUARD_REL = Path(".claude") / "hooks" / "vep_guard.py"
SKILL_REL = Path(".claude") / "skills" / "vep"
SKILL_FILES = ("SKILL.md", "workflows/register-and-verify.md", "workflows/explain-failure.md", "workflows/retrieve-evidence.md", "reference/errors.md")
HOOK_MATCHER = "Edit|Write|MultiEdit|NotebookEdit|Bash"
AUTHORITY_DEFAULT = ("read", "register")
AUTHORITY_EVALUATING = ("read", "register", "evaluate", "export")


class IntegrationConflict(VepError):
    """An existing file or setting differs from what would be installed; nothing was changed."""


def _asset(rel: str) -> bytes:
    return (resources.files("vep") / "assets" / "claude" / rel).read_bytes()


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


PRIVATE_FILE, PRIVATE_DIR, EXEC_PRIVATE, PUBLIC_FILE = 0o600, 0o700, 0o700, 0o644


def _check_target(root: Path, path: Path) -> str | None:
    """None if `path` may be written: an absent path, or a regular file (never a symlink or special file) whose directory resolves inside `root`."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    except OSError as exc:
        return f"{path.name}: {exc.__class__.__name__}"
    if st is not None and not stat.S_ISREG(st.st_mode):
        return f"{path.relative_to(root).as_posix()} is a symlink or not a regular file; refusing to write through it"
    parent = os.path.realpath(path.parent)
    if parent != str(root) and not parent.startswith(str(root) + os.sep):
        return f"{path.relative_to(root).as_posix()} resolves outside the project; refusing"
    return None


def _atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    """Write `data` to `path` atomically. The temporary file is created exclusively with an unpredictable name and mode 0600 (so it is never
    readable by others, whatever the umask), written completely, synced, given its final mode, then renamed over the destination. The final mode is
    `mode` if given, else the destination's existing permission bits (never widened), else 0600. Failure leaves the old destination untouched and no temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = stat.S_IMODE(os.lstat(path).st_mode)
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise IntegrationConflict(f"{path.name} is not a regular file; refusing to write through it")
    except FileNotFoundError:
        existing = None
    final = mode if mode is not None else (existing if existing is not None else PRIVATE_FILE)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.vep-tmp-")  # O_EXCL, 0600
    try:
        with os.fdopen(fd, "wb") as fh:
            view = memoryview(data)
            while view:
                n = os.write(fh.fileno(), view)
                if n <= 0:
                    raise OSError("short write")
                view = view[n:]
            fh.flush()
            os.fsync(fh.fileno())
            os.fchmod(fh.fileno(), final)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:  # make the rename durable; best effort (not supported everywhere)
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, PRIVATE_DIR)


def server_entry(authority: tuple[str, ...] = AUTHORITY_DEFAULT, unisolated_execution: bool = False, command: list[str] | None = None) -> dict:
    cmd = command or ([shutil.which("vep-mcp")] if shutil.which("vep-mcp") else [sys.executable, "-m", "vep.mcp_server"])
    args = cmd[1:] + ["--root", "${CLAUDE_PROJECT_DIR:-.}", "--authority", ",".join(authority)]
    if unisolated_execution:
        args.append("--trusted-local-execution")
    return {"command": cmd[0], "args": args}


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except ValueError as exc:
        raise IntegrationConflict(f"{path} is not valid JSON ({exc}); fix or move it, nothing was changed") from exc
    if not isinstance(data, dict):
        raise IntegrationConflict(f"{path} is not a JSON object; nothing was changed")
    return data


def _dump(d: dict) -> bytes:
    return (json.dumps(d, indent=2, sort_keys=False) + "\n").encode()


def _guard_hook_entry() -> dict:
    return {"matcher": HOOK_MATCHER, "hooks": [{"type": "command", "command": f'python3 "$CLAUDE_PROJECT_DIR/{GUARD_REL.as_posix()}"', "timeout": 10}]}


def _is_guard(group: dict) -> bool:
    return any(GUARD_MARK in str(h.get("command", "")) for h in group.get("hooks", []) if isinstance(h, dict))


def _claude_md_block() -> str:
    return f"{BEGIN}\n{_asset('claude_md_snippet.md').decode().rstrip()}\n{END}\n"


def _load_manifest(root: Path) -> dict:
    p = root / MANIFEST
    return json.loads(p.read_text()) if p.exists() else {}


def _backup(root: Path, stamp: str, rel: Path, actions: list) -> None:
    """Copy the original (possibly confidential) file into a private backup tree: directories 0700, files 0600, symlinks never followed."""
    src = root / rel
    if not os.path.lexists(src):
        return
    if (why := _check_target(root, src)):
        raise IntegrationConflict(why)
    (root / ".claude").mkdir(exist_ok=True)
    base = root / ".claude" / "vep-backups"
    dst_dir = (base / stamp / rel).parent
    cur = base
    _private_dir(cur)
    for part in dst_dir.relative_to(base).parts:
        cur = cur / part
        _private_dir(cur)
    dst = dst_dir / rel.name
    _atomic_write(dst, src.read_bytes(), PRIVATE_FILE)
    actions.append({"backup": str(rel), "to": str(dst.relative_to(root))})


def install(project: str | Path, *, authority: tuple[str, ...] = AUTHORITY_DEFAULT, unisolated_execution: bool = False, hooks: bool = True,
            claude_md: bool = True, force: bool = False, dry_run: bool = False, command: list[str] | None = None) -> dict:
    root = Path(project).resolve()
    if not root.is_dir():
        raise IntegrationConflict(f"{root} is not a directory")
    if unisolated_execution and "evaluate" not in authority:
        raise IntegrationConflict("--trusted-local-execution only makes sense together with the 'evaluate' authority")
    prev = _load_manifest(root)
    prev_files = prev.get("files", {})
    stamp = time.strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}-{time.time_ns() % 10**6:06d}"
    plan: list[dict] = []
    conflicts: list[str] = []
    writes: list[tuple[Path, bytes, int | None]] = []
    files_meta: dict[str, str] = {}

    def want_file(rel: Path, data: bytes, mode: int | None = None) -> None:
        target = root / rel
        key = rel.as_posix()
        files_meta[key] = _sha(data)
        if (why := _check_target(root, target)):
            conflicts.append(why); return
        if not target.exists():
            plan.append({"file": key, "action": "create"}); writes.append((target, data, mode)); return
        cur = _sha(target.read_bytes())
        if cur == _sha(data):
            plan.append({"file": key, "action": "unchanged"}); return
        if prev_files.get(key) == cur:
            plan.append({"file": key, "action": "update"}); writes.append((target, data, mode)); return
        if force:
            plan.append({"file": key, "action": "replace-with-backup"}); writes.append((target, data, mode)); return
        conflicts.append(f"{key} exists and was not installed by VEP (use --force to replace it; a backup is kept)")

    for f in SKILL_FILES:
        want_file(SKILL_REL / f, _asset("skill/" + f), PUBLIC_FILE)
    if hooks:
        want_file(GUARD_REL, _asset("vep_guard.py"), EXEC_PRIVATE)

    # .mcp.json
    mcp_path = root / ".mcp.json"
    for tp in (mcp_path, root / "CLAUDE.md", root / ".claude" / "settings.json", root / MANIFEST):
        if (why := _check_target(root, tp)):
            raise IntegrationConflict(why)
    mcp = _read_json(mcp_path)
    entry = server_entry(authority, unisolated_execution, command)
    servers = mcp.setdefault("mcpServers", {})
    mcp_action = "create" if SERVER not in servers else None
    if SERVER in servers:
        if servers[SERVER] == entry:
            mcp_action = "unchanged"
        elif prev.get("mcp_entry_sha") == _sha(json.dumps(servers[SERVER], sort_keys=True).encode()):
            mcp_action = "update"
        elif force:
            mcp_action = "replace-with-backup"
        else:
            conflicts.append(f".mcp.json already defines a server named {SERVER!r} that VEP did not install (use --force to replace it; a backup is kept)")
    if mcp_action and mcp_action != "unchanged" and not conflicts:
        servers[SERVER] = entry
    plan.append({"file": ".mcp.json", "action": mcp_action or "conflict"})

    # CLAUDE.md
    md_path = root / "CLAUDE.md"
    md_new = md_old = None
    if claude_md:
        md_old = md_path.read_text() if md_path.exists() else ""
        block = _claude_md_block()
        if BEGIN in md_old:
            s, e = md_old.index(BEGIN), md_old.index(END, md_old.index(BEGIN)) + len(END)
            md_new = md_old[:s] + block.rstrip("\n") + md_old[e:]
        else:
            md_new = md_old + ("" if not md_old or md_old.endswith("\n\n") else ("\n" if md_old.endswith("\n") else "\n\n")) + block
        plan.append({"file": "CLAUDE.md", "action": "unchanged" if md_new == md_old else ("update" if md_old else "create")})

    # settings hook
    set_path = root / ".claude" / "settings.json"
    settings = _read_json(set_path)
    settings_new = None
    if hooks:
        pre = settings.setdefault("hooks", {}).setdefault("PreToolUse", [])
        if not isinstance(pre, list):
            raise IntegrationConflict(".claude/settings.json: hooks.PreToolUse is not a list; nothing was changed")
        mine = [g for g in pre if isinstance(g, dict) and _is_guard(g)]
        if mine == [_guard_hook_entry()]:
            plan.append({"file": ".claude/settings.json", "action": "unchanged"})
        else:
            pre[:] = [g for g in pre if not (isinstance(g, dict) and _is_guard(g))] + [_guard_hook_entry()]
            settings_new = _dump(settings)
            plan.append({"file": ".claude/settings.json", "action": "update" if mine else ("update" if set_path.exists() else "create")})

    report = {"project": str(root), "dry_run": dry_run, "authority": list(authority), "unisolated_execution": unisolated_execution,
              "plan": plan, "conflicts": conflicts}
    if conflicts:
        report["status"] = "CONFLICT"
        return report
    if dry_run:
        report["status"] = "DRY_RUN"
        return report

    backups: list = []
    for target, data, mode in writes:
        if target.exists():
            _backup(root, stamp, target.relative_to(root), backups)
        _atomic_write(target, data, mode)
    if mcp_action not in (None, "unchanged"):
        if mcp_path.exists():
            _backup(root, stamp, Path(".mcp.json"), backups)
        _atomic_write(mcp_path, _dump(mcp), PRIVATE_FILE)
    if claude_md and md_new != md_old:
        if md_path.exists():
            _backup(root, stamp, Path("CLAUDE.md"), backups)
        _atomic_write(md_path, md_new.encode(), None if md_path.exists() else PUBLIC_FILE)
    if settings_new is not None:
        if set_path.exists():
            _backup(root, stamp, Path(".claude/settings.json"), backups)
        _atomic_write(set_path, settings_new, PRIVATE_FILE)
    _atomic_write(root / MANIFEST, _dump({
        "installed_by": "vep claude install", "files": files_meta, "mcp_entry_sha": _sha(json.dumps(entry, sort_keys=True).encode()),
        "claude_md": bool(claude_md), "hooks": bool(hooks), "authority": list(authority), "unisolated_execution": unisolated_execution}), PRIVATE_FILE)
    report.update(status="INSTALLED", backups=backups)
    return report


def status(project: str | Path) -> dict:
    root = Path(project).resolve()
    m = _load_manifest(root)
    out: dict = {"project": str(root), "installed": bool(m), "components": {}}
    comp = out["components"]
    for key, sha in m.get("files", {}).items():
        p = root / key
        comp[key] = "missing" if not p.exists() else ("ok" if _sha(p.read_bytes()) == sha else "modified")
    try:
        servers = _read_json(root / ".mcp.json").get("mcpServers", {})
        e = servers.get(SERVER)
        comp[".mcp.json"] = "absent" if e is None else ("ok" if m and _sha(json.dumps(e, sort_keys=True).encode()) == m.get("mcp_entry_sha") else "differs-from-installed")
        if e is not None:  # never echo an entry VEP did not write: it may carry the user's tokens
            out["server_entry"] = e if comp[".mcp.json"] == "ok" else {"redacted": True, "keys": sorted(e) if isinstance(e, dict) else []}
    except IntegrationConflict as exc:
        comp[".mcp.json"] = f"unreadable: {exc}"
    md = root / "CLAUDE.md"
    comp["CLAUDE.md"] = "ok" if md.exists() and _claude_md_block().rstrip("\n") in md.read_text() else ("absent" if not md.exists() or BEGIN not in md.read_text() else "modified")
    try:
        pre = _read_json(root / ".claude" / "settings.json").get("hooks", {}).get("PreToolUse", [])
        mine = [g for g in pre if isinstance(g, dict) and _is_guard(g)]
        comp["hook:PreToolUse"] = "absent" if not mine else ("ok" if mine == [_guard_hook_entry()] else "modified")
    except IntegrationConflict as exc:
        comp["hook:PreToolUse"] = f"unreadable: {exc}"
    if m:
        out["authority"], out["unisolated_execution"] = m.get("authority"), m.get("unisolated_execution", m.get("trusted_local_execution"))
    return out


def uninstall(project: str | Path, *, dry_run: bool = False) -> dict:
    root = Path(project).resolve()
    m = _load_manifest(root)
    if not m:
        return {"project": str(root), "status": "NOT_INSTALLED", "removed": [], "kept": []}
    removed: list[str] = []
    kept: list[str] = []
    for key, sha in m.get("files", {}).items():
        p = root / key
        if not p.exists():
            continue
        if _sha(p.read_bytes()) == sha:
            removed.append(key)
            if not dry_run:
                p.unlink()
        else:
            kept.append(f"{key} (modified since install)")
    mcp_path = root / ".mcp.json"
    try:
        mcp = _read_json(mcp_path)
        e = mcp.get("mcpServers", {}).get(SERVER)
        if e is not None:
            if _sha(json.dumps(e, sort_keys=True).encode()) == m.get("mcp_entry_sha"):
                removed.append(".mcp.json:mcpServers.vep")
                if not dry_run:
                    del mcp["mcpServers"][SERVER]
                    if not mcp["mcpServers"]:
                        del mcp["mcpServers"]
                    if mcp:
                        _atomic_write(mcp_path, _dump(mcp))
                    else:
                        mcp_path.unlink()
            else:
                kept.append(".mcp.json:mcpServers.vep (modified since install)")
    except IntegrationConflict as exc:
        kept.append(f".mcp.json ({exc})")
    md = root / "CLAUDE.md"
    if m.get("claude_md") and md.exists() and BEGIN in md.read_text():
        text = md.read_text()
        s, e = text.index(BEGIN), text.index(END, text.index(BEGIN)) + len(END)
        if text[s:e] + "\n" == _claude_md_block() or text[s:e] == _claude_md_block().rstrip("\n"):
            removed.append("CLAUDE.md:vep block")
            if not dry_run:
                rest = (text[:s].rstrip("\n") + "\n" + text[e:].lstrip("\n")).strip("\n")
                if rest:
                    _atomic_write(md, (rest + "\n").encode())
                else:
                    md.unlink()
        else:
            kept.append("CLAUDE.md:vep block (modified since install)")
    set_path = root / ".claude" / "settings.json"
    if m.get("hooks") and set_path.exists():
        try:
            st = _read_json(set_path)
            pre = st.get("hooks", {}).get("PreToolUse", [])
            mine = [g for g in pre if isinstance(g, dict) and _is_guard(g)]
            if mine == [_guard_hook_entry()]:
                removed.append(".claude/settings.json:PreToolUse vep_guard")
                if not dry_run:
                    pre[:] = [g for g in pre if g not in mine]
                    if not pre:
                        del st["hooks"]["PreToolUse"]
                    if not st["hooks"]:
                        del st["hooks"]
                    if st:
                        _atomic_write(set_path, _dump(st))
                    else:
                        set_path.unlink()
            elif mine:
                kept.append(".claude/settings.json:PreToolUse vep_guard (modified since install)")
        except IntegrationConflict as exc:
            kept.append(f".claude/settings.json ({exc})")
    if not dry_run:
        (root / MANIFEST).unlink()
        for d in sorted({(root / k).parent for k in m.get("files", {})}, key=lambda x: -len(x.parts)):
            while d != root and d.exists() and not any(d.iterdir()):
                d.rmdir(); d = d.parent
    return {"project": str(root), "status": "UNINSTALLED" if not dry_run else "DRY_RUN", "removed": removed, "kept": kept,
            "note": "backups under .claude/vep-backups are left in place"}


def write_plugin(out: str | Path, *, version: str) -> dict:
    """Write a Claude Code plugin directory (skill + MCP server + guard hook). Read-only authority; the user raises it by editing .mcp.json."""
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir()):
        raise IntegrationConflict(f"{out} is not empty")
    files: dict[str, bytes] = {".claude-plugin/plugin.json": _dump({
        "name": "vep", "version": version, "description": "Verify code changes with VEP: protected evaluation, exact evidence, portable bundles.",
        "license": "Apache-2.0", "author": {"name": "SiteBorne"}})}
    for f in SKILL_FILES:
        files["skills/vep/" + f] = _asset("skill/" + f)
    files["hooks/vep_guard.py"] = _asset("vep_guard.py")
    files["hooks/hooks.json"] = _dump({"hooks": {"PreToolUse": [{"matcher": HOOK_MATCHER, "hooks": [
        {"type": "command", "command": 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/vep_guard.py"', "timeout": 10}]}]}})
    entry = server_entry(AUTHORITY_DEFAULT, False)
    files[".mcp.json"] = _dump({"mcpServers": {SERVER: entry}})
    for rel, data in files.items():
        _atomic_write(out / rel, data, EXEC_PRIVATE if rel.endswith("vep_guard.py") else PRIVATE_FILE if rel in (".mcp.json", "hooks/hooks.json") else PUBLIC_FILE)
    return {"plugin_dir": str(out), "files": sorted(files), "authority": list(AUTHORITY_DEFAULT),
            "note": "load with `claude --plugin-dir <dir>`; the server needs `vep-mcp` (pip install 'vep[mcp]') on PATH"}
