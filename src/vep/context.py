"""Deterministic, lossless context selection with explicit budgets. No embeddings, no external APIs."""
from __future__ import annotations

import math

from .errors import ContextBudgetExceeded, SnapshotError
from .objects import VEPObject
from .policies import load_policy
from .snapshots import entries_of, validate_rel_path
from .workspace import Workspace

BYTES_PER_TOKEN = 4  # approximation only; recorded in the manifest as the estimation method


def estimate_tokens(size_bytes: int) -> int:
    return math.ceil(size_bytes / BYTES_PER_TOKEN)


def build_context(ws: Workspace, snapshot_id: str, policy_id: str, max_tokens: int,
                  required: list[str] | None = None, requested: list[str] | None = None,
                  keyword_query: str | None = None, include_protected: bool = True) -> VEPObject:
    snap = ws.get_object(snapshot_id, "Snapshot")
    policy = load_policy(ws, policy_id)
    ents = entries_of(snap)
    plan: list[tuple[str, str, bool]] = []  # (path, reason, required)
    seen: set[str] = set()

    def add(path: str, reason: str, req: bool) -> None:
        validate_rel_path(path)
        if path not in ents:
            raise SnapshotError(f"path not in snapshot: {path}")
        if path not in seen:
            seen.add(path)
            plan.append((path, reason, req))

    for p in sorted(required or []):
        add(p, "required:explicit", True)
    if include_protected:
        for p in sorted(policy["required_tests"]):
            if p in ents:
                add(p, "required:policy-protected", True)
    for p in requested or []:
        add(p, "requested", False)
    if keyword_query:
        terms = [t for t in keyword_query.lower().split() if t]
        scored = []
        for p, e in ents.items():
            if p in seen:
                continue
            text = (p + "\n" + ws.cas.get(e["digest"]).decode("utf-8", "ignore")).lower()
            score = sum(text.count(t) for t in terms)
            if score:
                scored.append((-score, p))
        for _, p in sorted(scored):
            add(p, "keyword:experimental", False)

    entries, excluded, total = [], [], 0
    for path, reason, req in plan:
        e = ents[path]
        toks = estimate_tokens(len(ws.cas.get(e["digest"])))
        if total + toks > max_tokens:
            if req:
                raise ContextBudgetExceeded(
                    f"required path {path} ({toks} tokens) does not fit in budget {max_tokens}; "
                    "protected requirements are never truncated")
            excluded.append({"path": path, "reason": "over_budget", "tokens": toks})
            continue
        total += toks
        entries.append({"path": path, "digest": e["digest"], "tokens": toks, "reason": reason, "required": req})
    manifest = VEPObject.create("ContextManifest", {
        "snapshot_id": snapshot_id, "policy_id": policy_id, "max_context_tokens": max_tokens,
        "token_method": "approx_utf8_bytes_div_4", "entries": entries, "excluded": excluded,
        "total_tokens": total})
    ws.put_object(manifest)
    return manifest
