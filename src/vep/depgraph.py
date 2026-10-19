"""Inspectable dependency / conflict graph, evidence validity, and composite-candidate handling.

Edge types and their epistemic basis:
  SOURCE_DEPENDENCY    derived from static Python imports in the snapshot (basis STATIC_IMPORT). Dynamic imports,
                       file reads, subprocesses and non-Python files are NOT seen.
  BUILD_DEPENDENCY     declared by the caller (basis DECLARED)
  CONTRACT_DEPENDENCY  declared by the caller: path -> contract file(s) it relies on (basis DECLARED)
  EVIDENCE_DEPENDENCY  evidence -> the exact snapshot and policy it is bound to (basis SIGNED_BINDING)
  WORK_CLAIM_CONFLICT  two claims whose path scopes overlap (basis PATH_OVERLAP)

No semantic dependency is invented. Because static analysis cannot establish behavioural independence,
evidence reuse is EXACT_ONLY: evidence is valid for the identical snapshot, policy and trust level, and for
nothing else. Impact analysis is used only to PRIORITISE tests, never to skip mandatory ones.
A textually clean merge is never treated as behaviourally compatible: composites always need evaluation.
"""
from __future__ import annotations

import ast
from typing import Iterable

from . import candidates
from .errors import StateError
from .snapshots import diff, entries_of
from .workspace import Workspace

EDGE_TYPES = ("SOURCE_DEPENDENCY", "BUILD_DEPENDENCY", "CONTRACT_DEPENDENCY", "EVIDENCE_DEPENDENCY",
              "WORK_CLAIM_CONFLICT")
REUSE_MODE = "EXACT_ONLY"


def _edge(kind: str, src: str, dst: str, basis: str) -> dict:
    return {"type": kind, "from": src, "to": dst, "basis": basis}


def _module_index(paths: Iterable[str]) -> dict[str, str]:
    idx: dict[str, str] = {}
    for p in paths:
        if not p.endswith(".py"):
            continue
        parts = p[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        # a module may be importable from any directory prefix used as an import root
        for k in range(len(parts)):
            if parts[k:]:
                idx.setdefault(".".join(parts[k:]), p)
    return idx


def _imports(src: str, path: str) -> set[str]:
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return set()
    pkg = path.split("/")[:-1]
    names: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                base = pkg[: len(pkg) - (n.level - 1)] if n.level - 1 <= len(pkg) else []
                mod = ".".join(base + ([n.module] if n.module else []))
            else:
                mod = n.module or ""
            if mod:
                names.add(mod)
                names.update(f"{mod}.{a.name}" for a in n.names)
            else:
                names.update(".".join(pkg + [a.name]) for a in n.names)
    return names


def build_graph(ws: Workspace, snapshot_id: str, *, build_deps: dict[str, list[str]] | None = None,
                contracts: dict[str, list[str]] | None = None) -> dict:
    snap = ws.get_object(snapshot_id, "Snapshot")
    ents = entries_of(snap)
    idx = _module_index(ents)
    edges: list[dict] = []
    for path, e in sorted(ents.items()):
        if not path.endswith(".py"):
            continue
        src = ws.cas.get(e["digest"]).decode("utf-8", "replace")
        targets = {idx[m] for m in _imports(src, path) if m in idx} - {path}
        edges += [_edge("SOURCE_DEPENDENCY", path, t, "STATIC_IMPORT") for t in sorted(targets)]
    for kind, decl in (("BUILD_DEPENDENCY", build_deps), ("CONTRACT_DEPENDENCY", contracts)):
        for src_path, targets in sorted((decl or {}).items()):
            for t in sorted(targets):
                if src_path in ents and t in ents:
                    edges.append(_edge(kind, src_path, t, "DECLARED"))
    return {"snapshot_id": snapshot_id, "nodes": sorted(ents), "edges": edges,
            "limits": "SOURCE_DEPENDENCY covers static Python imports only"}


def dependents_of(graph: dict, changed: Iterable[str]) -> set[str]:
    """Reverse transitive closure: everything that (transitively) depends on a changed path, incl. itself."""
    rev: dict[str, set[str]] = {}
    for e in graph["edges"]:
        if e["type"] in ("SOURCE_DEPENDENCY", "BUILD_DEPENDENCY", "CONTRACT_DEPENDENCY"):
            rev.setdefault(e["to"], set()).add(e["from"])
    seen, stack = set(changed), list(changed)
    while stack:
        for d in rev.get(stack.pop(), ()):
            if d not in seen:
                seen.add(d)
                stack.append(d)
    return seen


def impact(ws: Workspace, graph: dict, old_snapshot_id: str, new_snapshot_id: str) -> dict:
    d = diff(ws.get_object(old_snapshot_id, "Snapshot"), ws.get_object(new_snapshot_id, "Snapshot"))
    changed = sorted(set(d["added"]) | set(d["removed"]) | set(d["modified"]) | set(d["mode_changed"]))
    non_py = [p for p in changed if not p.endswith(".py")]
    affected = sorted(dependents_of(graph, changed))
    return {"changed": changed, "affected_by_static_analysis": affected,
            "affected_tests": [p for p in affected if "test" in p.rsplit("/", 1)[-1]],
            "unanalysable_changes": non_py,
            "semantic_impact_established": False,
            "required_evaluation": "FULL",  # static analysis never narrows the mandatory evaluation
            "note": "affected_tests is a prioritisation hint only"}


# ---------------------------------------------------------------- evidence validity
def evidence_validity(ws: Workspace, evidence_id: str, *, snapshot_id: str, policy_id: str,
                      trust_level: str | None = None) -> dict:
    """Is previously signed evidence usable for this exact (snapshot, policy, trust)? EXACT_ONLY, fail closed."""
    from .evidence import load_signed
    with ws.db.read() as c:
        row = c.execute("SELECT envelope_digest FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if row is None:
        return {"valid": False, "reasons": ["EVIDENCE_UNKNOWN"], "reuse_mode": REUSE_MODE}
    ev = load_signed(ws, row["envelope_digest"], "Evidence")  # re-verifies signature and integrity
    reasons = []
    if ev["verdict"] != "PASS":
        reasons.append("VERDICT_NOT_PASS")
    if ev["snapshot_id"] != snapshot_id:
        reasons.append("SNAPSHOT_CHANGED")
    if ev["policy_id"] != policy_id:
        reasons.append("POLICY_CHANGED")
    if trust_level and ev["trust_level"] != trust_level:
        reasons.append("TRUST_LEVEL_MISMATCH")
    return {"valid": not reasons, "reasons": reasons, "reuse_mode": REUSE_MODE,
            "edge": _edge("EVIDENCE_DEPENDENCY", evidence_id, ev["snapshot_id"], "SIGNED_BINDING")}


def invalidated_evidence(ws: Workspace, new_snapshot_id: str) -> list[dict]:
    """All PASS evidence whose bound snapshot differs from `new_snapshot_id` for the same objective."""
    with ws.db.read() as c:
        rows = c.execute("SELECT id, snapshot_id, objective_id FROM evidence WHERE verdict='PASS' AND snapshot_id<>?",
                         (new_snapshot_id,)).fetchall()
    return [{"evidence_id": r["id"], "bound_snapshot": r["snapshot_id"], "reason": "SNAPSHOT_CHANGED"} for r in rows]


# ---------------------------------------------------------------- claims
def claim_relations(graph: dict, claim_a, claim_b) -> list[dict]:
    """Relations between two WorkClaims: path overlap (conflict) and dependency in either direction."""
    out = []
    overlap = candidates.claims_overlap(claim_a, claim_b)
    if overlap:
        out.append({"type": "WORK_CLAIM_CONFLICT", "paths": overlap, "basis": "PATH_OVERLAP"})
    for (x, y, label) in ((claim_a, claim_b, "B_DEPENDS_ON_A"), (claim_b, claim_a, "A_DEPENDS_ON_B")):
        deps = dependents_of(graph, x["paths"]) - set(x["paths"])
        hit = sorted(p for p in deps if any(p == q or p.startswith(q.rstrip("/") + "/") for q in y["paths"]))
        if hit:
            kinds = sorted({e["type"] for e in graph["edges"] if e["from"] in hit and e["to"] in dependents_of(graph, x["paths"])})
            out.append({"type": kinds[0] if kinds else "SOURCE_DEPENDENCY", "direction": label, "paths": hit})
    return out


def schedule(graph: dict, claims: list) -> dict:
    """Greedy grouping: claims in one wave have no overlap and no dependency between them. Conservative."""
    waves: list[list] = []
    for c in claims:
        for w in waves:
            if all(not claim_relations(graph, c, o) for o in w):
                w.append(c)
                break
        else:
            waves.append([c])
    return {"waves": [[c["claimant"] for c in w] for w in waves],
            "parallel_safe_within_wave": True, "note": "waves must run in order; wave members are statically independent only"}


# ---------------------------------------------------------------- composition
def compose_candidates(ws: Workspace, objective_id: str, cand_a: str, cand_b: str, author: str = "vep-composer") -> dict:
    """Three-way compose over the objective's base. Never certifies; a clean merge yields a NEW candidate
    that must pass full evaluation. Conflicts yield deterministic replanning instructions."""
    obj = ws.get_object(objective_id, "Objective")
    for c in (cand_a, cand_b):
        if ws.get_object(c, "Candidate")["objective_id"] != objective_id:
            raise StateError(f"{c} belongs to a different objective")
    res = candidates.compose(ws, obj["base_snapshot_id"], cand_a, cand_b)
    if res["conflicts"]:
        return {"status": "CONFLICT", "conflicts": res["conflicts"], "composite_candidate_id": None,
                "replan": {"action": "REBASE_ONE_CANDIDATE", "paths": res["conflicts"],
                           "instruction": "re-run the later task against the other candidate's snapshot, or split the claim scopes"}}
    comp = candidates.register_candidate(ws, objective_id, res["snapshot"].id, author, parent_candidate_id=cand_a)
    return {"status": "TEXTUALLY_CLEAN", "composite_candidate_id": comp.id, "composite_snapshot_id": res["snapshot"].id,
            "requires_composite_evaluation": True,
            "note": "textual cleanliness does not imply behavioural compatibility; neither parent's evidence applies"}
