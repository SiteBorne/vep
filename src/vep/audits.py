"""Policy-defined static audits for readiness / aggregate-flag consistency (F12-F16).

Audit specs live in the frozen policy, never in the candidate. No product-specific field names:
every rule addresses data through dotted JSON paths supplied by the policy.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import CanonicalError, SchemaError
from .objects import VEPObject
from .snapshots import entries_of
from .workspace import Workspace

_MISSING = object()
RULE_TYPES = {"aggregate_all", "implies", "forbid_when", "forbid_values", "require_present", "min_value_count"}


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalError(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def parse_audit_json(data: bytes) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes,
                          parse_constant=lambda c: (_ for _ in ()).throw(CanonicalError("non-finite number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalError(f"unparseable audit input: {exc}") from exc


def get_path(doc: Any, path: str) -> Any:
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return _MISSING
    return cur


def _truthy_flag(v: Any, flag: str | None) -> bool:
    if isinstance(v, dict) and flag:
        v = v.get(flag, _MISSING)
    return v is True  # strictly boolean true; "yes", 1, "ready" never count


def _cond(doc: Any, cond: dict) -> bool:
    v = get_path(doc, cond["path"])
    if v is _MISSING:
        return False
    if "equals" in cond:
        return v == cond["equals"] and type(v) is type(cond["equals"])
    if "in" in cond:
        return v in cond["in"]
    return bool(v)


def evaluate_rule(doc: Any, rule: dict) -> list[str]:
    t = rule.get("type")
    if t not in RULE_TYPES:
        raise SchemaError(f"unknown audit rule type {t!r}")
    f: list[str] = []
    if t == "aggregate_all":
        agg = get_path(doc, rule["aggregate"])
        comps = get_path(doc, rule["components"])
        if agg is _MISSING or comps is _MISSING:
            return [f"AGGREGATE_FIELDS_MISSING:{rule['aggregate']}/{rule['components']}"]
        items = list(comps.values()) if isinstance(comps, dict) else comps if isinstance(comps, list) else None
        if items is None:
            return [f"COMPONENTS_NOT_COLLECTION:{rule['components']}"]
        if len(items) < rule.get("min_components", 1):
            f.append(f"TOO_FEW_COMPONENTS:{len(items)}")
        all_ok = bool(items) and all(_truthy_flag(i, rule.get("component_flag")) for i in items)
        if agg is True and not all_ok:
            f.append(f"AGGREGATE_TRUE_BUT_COMPONENT_NOT_READY:{rule['aggregate']}")
        if agg is False and all_ok and rule.get("strict", True):
            f.append(f"AGGREGATE_FALSE_BUT_ALL_COMPONENTS_READY:{rule['aggregate']}")
        if agg not in (True, False):
            f.append(f"AGGREGATE_NOT_BOOLEAN:{rule['aggregate']}")
    elif t == "implies":
        if _cond(doc, rule["if"]):
            then = rule["then"]
            if get_path(doc, then["path"]) is _MISSING or not _cond(doc, then):
                f.append(f"IMPLICATION_VIOLATED:{rule['if']['path']}->{then['path']}")
    elif t == "forbid_when":
        if _cond(doc, rule["when"]):
            v = get_path(doc, rule["forbidden"]["path"])
            if v is not _MISSING and v in rule["forbidden"]["in"]:
                f.append(f"FORBIDDEN_VALUE:{rule['forbidden']['path']}={v!r}")
    elif t == "forbid_values":
        v = get_path(doc, rule["path"])
        if v is not _MISSING:
            seq = v if isinstance(v, list) else [v]
            for item in seq:
                if any(isinstance(item, str) and bad in item for bad in rule["values"]):
                    f.append(f"FORBIDDEN_ENTRY:{rule['path']}:{item}")
    elif t == "require_present":
        if get_path(doc, rule["path"]) is _MISSING:
            f.append(f"REQUIRED_FIELD_MISSING:{rule['path']}")
    elif t == "min_value_count":
        v = get_path(doc, rule["path"])
        if v is _MISSING or not isinstance(v, (list, dict)) or len(v) < rule["min"]:
            f.append(f"INSUFFICIENT_ITEMS:{rule['path']}")
    return f


def audit_document(doc: Any, audit: dict) -> list[str]:
    findings = []
    for rule in audit.get("rules", []):
        try:
            findings += evaluate_rule(doc, rule)
        except (KeyError, TypeError) as exc:  # malformed rule fails closed
            findings.append(f"MALFORMED_RULE:{exc!r}")
    return findings


def run_audits_on_snapshot(ws: Workspace, snap: VEPObject, audits: list[dict]) -> dict[str, list[str]]:
    ents = entries_of(snap)
    results: dict[str, list[str]] = {}
    for a in audits:
        aid = a.get("id", "unnamed")
        path = a.get("file", "")
        if path not in ents:
            results[aid] = [f"AUDIT_FILE_MISSING:{path}"]  # fail closed
            continue
        try:
            doc = parse_audit_json(ws.cas.get(ents[path]["digest"]))
        except CanonicalError as exc:
            results[aid] = [f"AUDIT_FILE_INVALID:{exc}"]
            continue
        results[aid] = audit_document(doc, a)
    return results


def run_audits_on_file(path: Path, audit: dict) -> list[str]:
    try:
        doc = parse_audit_json(Path(path).read_bytes())
    except (OSError, CanonicalError) as exc:
        return [f"AUDIT_FILE_INVALID:{exc}"]
    return audit_document(doc, audit)
