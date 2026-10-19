"""VEP-C1 canonical serialization and domain-separated SHA-256 identities.

Rules (version 1):
* Allowed values: null, bool, int (|n| < 2**63), str, list, dict with str keys.
* Floats are rejected outright (no NaN/Infinity, no ambiguous monetary floats);
  decimals travel as strings.
* Objects are serialized with keys sorted by Unicode code point, no whitespace,
  UTF-8 without BOM, no ASCII escaping.
* Parsing rejects duplicate keys, floats and non-finite constants.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .errors import CanonicalError

CANON_VERSION = 1
MAX_INT = 2**63 - 1
MAX_DEPTH = 64
HEX64 = re.compile(r"^[0-9a-f]{64}\Z")  # \Z, not $: "$" would accept a trailing newline


def _check(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("nesting too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_INT:
            raise CanonicalError("integer out of range")
        return
    if isinstance(value, float):
        raise CanonicalError("floats are not permitted; use int or decimal string")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalError("string is not valid Unicode") from exc
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError("object keys must be strings")
            _check(k, depth + 1)
            _check(v, depth + 1)
        return
    raise CanonicalError(f"unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalError(f"duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _reject_const(name: str) -> Any:
    raise CanonicalError(f"non-finite number {name} not permitted")


def _reject_float(text: str) -> Any:
    raise CanonicalError(f"floating-point number {text!r} not permitted")


def strict_loads(data: bytes | str) -> Any:
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError("input is not UTF-8") from exc
        if data.startswith("﻿"):
            raise CanonicalError("BOM not permitted")
    try:
        value = json.loads(
            data,
            object_pairs_hook=_no_dupes,
            parse_constant=_reject_const,
            parse_float=_reject_float,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalError(f"invalid JSON: {exc}") from exc
    except RecursionError as exc:
        raise CanonicalError("nesting too deep") from exc
    _check(value)
    return value


def domain_hash(domain: str, data: bytes) -> str:
    """SHA-256 over an unambiguous, length-prefixed (domain, data) encoding."""
    d = domain.encode("utf-8")
    h = hashlib.sha256()
    h.update(b"vep-id\x00")
    h.update(len(d).to_bytes(4, "big"))
    h.update(d)
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)
    return h.hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and HEX64.match(value) is not None
