"""Versioned protocol objects with validated fields and domain-separated identities.

Identity: ``<prefix>-<sha256>`` where the hash covers (domain, canonical fields) with
domain ``vep.<Type>.v<schema_version>``. Objects are immutable; mutable lifecycle state
(e.g. candidate status) lives in the database, never in the object.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from .canonical import canonical_bytes, domain_hash, is_digest, strict_loads
from .errors import SchemaError

SCHEMA_VERSION = 1
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")  # ASCII digits only; no trailing newline
DEC_RE = re.compile(r"^-?[0-9]+(\.[0-9]+)?\Z")

# kind -> description; fields: name -> (kind, required, options)
# kinds: str, int, bool, digest, id:<Type>, ts, decimal, list:<kind>, map:<kind>, json, enum
S = dict


def _f(kind: str, required: bool = True, **opts: Any) -> tuple:
    return (kind, required, opts)


SPECS: dict[str, dict[str, Any]] = {
    "Objective": S(prefix="obj", fields={
        "title": _f("str"), "description": _f("str", allow_empty=True),
        "base_snapshot_id": _f("id:Snapshot"), "policy_id": _f("id:ExecutionPolicy"),
        "created_by": _f("str"), "created_at": _f("ts")}),
    "Snapshot": S(prefix="snap", fields={
        "manifest_version": _f("int", min=1), "entries": _f("json")}),
    "WorkClaim": S(prefix="claim", fields={
        "objective_id": _f("id:Objective"), "claimant": _f("str"),
        "base_snapshot_id": _f("id:Snapshot"), "paths": _f("list:str"),
        "created_at": _f("ts"), "expires_at": _f("ts")}),
    "Candidate": S(prefix="cand", fields={
        "objective_id": _f("id:Objective"), "base_snapshot_id": _f("id:Snapshot"),
        "snapshot_id": _f("id:Snapshot"), "author": _f("str"),
        "parent_candidate_id": _f("id:Candidate", False),
        "work_claim_id": _f("id:WorkClaim", False), "created_at": _f("ts")}),
    "Action": S(prefix="act", fields={
        "argv": _f("list:str"), "input_snapshot_id": _f("id:Snapshot"),
        "policy_id": _f("id:ExecutionPolicy"), "runner_digest": _f("digest"),
        "env": _f("map:str"), "isolation": _f("enum", values=["NONE_TRUSTED_LOCAL", "DOCKER_GVISOR"])}),
    "Evidence": S(prefix="evd", fields={
        "candidate_id": _f("id:Candidate"), "objective_id": _f("id:Objective"),
        "snapshot_id": _f("id:Snapshot"), "policy_id": _f("id:ExecutionPolicy"),
        "action_id": _f("id:Action"), "runner_digest": _f("digest"),
        "argv": _f("list:str"), "exit_code": _f("int"),
        "verdict": _f("enum", values=["PASS", "FAIL"]),
        "tests_discovered": _f("int", min=0), "tests_run": _f("int", min=0),
        "tests_passed": _f("int", min=0), "tests_failed": _f("int", min=0),
        "tests_skipped": _f("int", min=0), "executed_ids_digest": _f("digest"),
        "stdout_digest": _f("digest"), "stderr_digest": _f("digest"),
        "staged_tree_snapshot_id": _f("id:Snapshot"),
        "isolation": _f("enum", values=["NONE_TRUSTED_LOCAL", "DOCKER_GVISOR"]),
        "started_at": _f("ts"), "finished_at": _f("ts"),
        "budget_reservation": _f("str")}),
    "Certificate": S(prefix="cert", fields={
        "candidate_id": _f("id:Candidate"), "objective_id": _f("id:Objective"),
        "snapshot_id": _f("id:Snapshot"), "policy_id": _f("id:ExecutionPolicy"),
        "evidence_id": _f("id:Evidence"), "evidence_envelope_digest": _f("digest"),
        "issuer_key_id": _f("digest"), "issued_at": _f("ts")}),
    "Observation": S(prefix="obs", fields={
        "subject": _f("str"), "metric": _f("str"), "value": _f("decimal"), "unit": _f("str"),
        "source": _f("enum", values=["measured", "simulated", "supplied"]),
        "observed_at": _f("ts")}),
    "TokenReceipt": S(prefix="rcpt", fields={
        "provider": _f("str"), "model": _f("str"), "pricing_version": _f("str"),
        "candidate_id": _f("id:Candidate"), "attempt": _f("int", min=0),
        "ordinary_input_tokens": _f("int", min=0), "cached_input_tokens": _f("int", min=0),
        "cache_write_tokens": _f("int", min=0), "output_tokens": _f("int", min=0),
        "reasoning_tokens_in_output": _f("int", min=0),
        "other_provider_charges": _f("decimal"),
        "prices_per_million": _f("map:decimal"),
        "usage_source": _f("enum", values=["provider_reported", "simulated", "local_estimate", "caller_supplied"]),
        "cost_usd": _f("decimal"), "context_id": _f("id:ContextManifest", False),
        "status": _f("enum", values=["RECORDED", "SETTLED"]),
        "idempotency_key": _f("str")}),
    "BudgetLease": S(prefix="lease", fields={
        "account_id": _f("str"), "reservation_key": _f("str"),
        "amount_micro_usd": _f("int", min=0), "created_at": _f("ts")}),
    "ContextManifest": S(prefix="ctx", fields={
        "snapshot_id": _f("id:Snapshot"), "policy_id": _f("id:ExecutionPolicy"),
        "max_context_tokens": _f("int", min=1),
        "token_method": _f("enum", values=["approx_utf8_bytes_div_4", "measured"]),
        "entries": _f("json"), "excluded": _f("json"), "total_tokens": _f("int", min=0)}),
    "ExecutionPolicy": S(prefix="pol", fields={
        "name": _f("str"), "policy_version": _f("int", min=1),
        "evaluator": _f("json"), "protected_patterns": _f("list:str"),
        "required_tests": _f("map:digest"), "limits": _f("json"), "audits": _f("json")}),
    "OptimizationExperiment": S(prefix="exp", fields={
        "name": _f("str"), "hypothesis": _f("str"), "metric": _f("str"),
        "baseline_label": _f("str"), "treatment_label": _f("str"),
        "data_source": _f("enum", values=["measured", "simulated"]),
        "adoption_rule": _f("str"), "alpha": _f("decimal"),
        "status": _f("enum", values=["PROPOSED", "RUNNING", "ADOPTED", "REJECTED", "INCONCLUSIVE"]),
        "created_at": _f("ts")}),
}
TRUST_LEVELS = ["TRUSTED_LOCAL", "ISOLATED_VERIFIED", "UNVERIFIED"]
ISOLATION_VALUES = ["NONE_TRUSTED_LOCAL", "DOCKER_GVISOR"]

# Schema versions are per type. Evidence and Certificate moved to v2 in package 0.4.0a1 (trust levels).
# v1 objects stay decodable (their identities never change) but carry no trust claim of their own.
LEGACY_SPECS: dict[tuple[str, int], dict[str, Any]] = {
    ("Evidence", 1): SPECS["Evidence"],
    ("Certificate", 1): SPECS["Certificate"],
}
CURRENT_VERSION: dict[str, int] = {"Evidence": 2, "Certificate": 2}
SUPPORTED_VERSIONS: dict[str, tuple[int, ...]] = {"Evidence": (1, 2), "Certificate": (1, 2)}

SPECS["Evidence"] = S(prefix="evd", fields={
    **SPECS["Evidence"]["fields"],
    "trust_level": _f("enum", values=TRUST_LEVELS),
    "evaluator_id": _f("str", max_len=256),
    "execution_environment": _f("json"),
    "isolation_attestation_digest": _f("digest", False)})
SPECS["Certificate"] = S(prefix="cert", fields={
    **SPECS["Certificate"]["fields"],
    "trust_level": _f("enum", values=TRUST_LEVELS), "evaluator_id": _f("str", max_len=256)})
SPECS["ExecutionPolicy"]["fields"]["required_trust"] = _f("enum", False, values=["TRUSTED_LOCAL", "ISOLATED_VERIFIED"])

PREFIX_TO_TYPE = {v["prefix"]: k for k, v in SPECS.items()}


def version_of(type_name: str) -> int:
    return CURRENT_VERSION.get(type_name, 1)


def spec_for(type_name: str, version: int) -> dict[str, Any]:
    if type_name not in SPECS:
        raise SchemaError(f"unknown object type {type_name!r}")
    if version not in SUPPORTED_VERSIONS.get(type_name, (1,)):
        raise SchemaError(f"UNSUPPORTED_SCHEMA_VERSION: {type_name} v{version!r}")
    if version == version_of(type_name):
        return SPECS[type_name]
    return LEGACY_SPECS[(type_name, version)]


def _check_trust_consistency(type_name: str, version: int, f: dict) -> None:
    """Cross-field rules: a trust level must be backed by matching isolation facts."""
    if version < 2 or type_name not in ("Evidence", "Certificate"):
        return
    tl = f["trust_level"]
    if type_name == "Evidence":
        att = "isolation_attestation_digest" in f
        if tl == "TRUSTED_LOCAL" and (f["isolation"] != "NONE_TRUSTED_LOCAL" or att):
            raise SchemaError("TRUSTED_LOCAL evidence must be non-isolated and carry no isolation attestation")
        if tl == "ISOLATED_VERIFIED" and (f["isolation"] != "DOCKER_GVISOR" or not att):
            raise SchemaError("ISOLATED_VERIFIED evidence requires DOCKER_GVISOR isolation and an attestation digest")
        if tl == "UNVERIFIED" and f["verdict"] == "PASS":
            raise SchemaError("UNVERIFIED evidence cannot carry a PASS verdict")
ID_RE = re.compile(r"^([a-z]+)-([0-9a-f]{64})\Z")


def parse_id(object_id: str) -> tuple[str, str]:
    m = ID_RE.match(object_id) if isinstance(object_id, str) else None
    if not m or m.group(1) not in PREFIX_TO_TYPE:
        raise SchemaError(f"malformed object id {object_id!r}")
    return PREFIX_TO_TYPE[m.group(1)], m.group(2)


def is_id_of(object_id: Any, type_name: str) -> bool:
    try:
        return parse_id(object_id)[0] == type_name
    except SchemaError:
        return False


def _validate_value(name: str, kind: str, opts: dict, value: Any) -> None:
    def bad(msg: str) -> SchemaError:
        return SchemaError(f"field {name!r}: {msg}")

    if kind == "str":
        if not isinstance(value, str) or (not value and not opts.get("allow_empty")):
            raise bad("expected non-empty string")
        if len(value) > opts.get("max_len", 65536):
            raise bad("string too long")
    elif kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise bad("expected integer")
        if "min" in opts and value < opts["min"]:
            raise bad(f"must be >= {opts['min']}")
    elif kind == "bool":
        if not isinstance(value, bool):
            raise bad("expected boolean")
    elif kind == "digest":
        if not is_digest(value):
            raise bad("expected 64 lowercase hex chars")
    elif kind.startswith("id:"):
        if not is_id_of(value, kind[3:]):
            raise bad(f"expected {kind[3:]} id")
    elif kind == "ts":
        if not isinstance(value, str) or not TS_RE.match(value):
            raise bad("expected UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
    elif kind == "decimal":
        if not isinstance(value, str) or not DEC_RE.match(value):
            raise bad("expected decimal string")
        try:
            Decimal(value)
        except InvalidOperation:
            raise bad("invalid decimal") from None
    elif kind == "enum":
        if value not in opts["values"]:
            raise bad(f"must be one of {opts['values']}")
    elif kind == "json":
        pass  # structurally validated by canonicalization
    elif kind.startswith("list:"):
        if not isinstance(value, list):
            raise bad("expected list")
        for i, item in enumerate(value):
            _validate_value(f"{name}[{i}]", kind[5:], opts, item)
    elif kind.startswith("map:"):
        if not isinstance(value, dict):
            raise bad("expected object")
        for k, item in value.items():
            _validate_value(f"{name}.{k}", kind[4:], {"allow_empty": True}, item)
    else:  # pragma: no cover
        raise SchemaError(f"unknown kind {kind}")


@dataclass(frozen=True)
class VEPObject:
    type: str
    schema_version: int
    _fields_bytes: bytes  # canonical bytes of the fields mapping (immutable)

    @property
    def fields(self) -> dict[str, Any]:
        return strict_loads(self._fields_bytes)

    @classmethod
    def create(cls, type_name: str, fields: dict[str, Any], schema_version: int | None = None) -> "VEPObject":
        version = version_of(type_name) if schema_version is None else schema_version
        spec = spec_for(type_name, version)
        if not isinstance(fields, dict):
            raise SchemaError("fields must be an object")
        fields = {k: v for k, v in fields.items()}
        specs = spec["fields"]
        unknown = set(fields) - set(specs)
        if unknown:
            raise SchemaError(f"unknown fields for {type_name}: {sorted(unknown)}")
        for name, (kind, required, opts) in specs.items():
            if name not in fields or fields[name] is None:
                if required:
                    raise SchemaError(f"missing required field {name!r}")
                fields.pop(name, None)  # optional absent == omitted, never null
                continue
            _validate_value(name, kind, opts, fields[name])
        _check_trust_consistency(type_name, version, fields)
        return cls(type_name, version, canonical_bytes(fields))

    @property
    def domain(self) -> str:
        return f"vep.{self.type}.v{self.schema_version}"

    @property
    def id(self) -> str:
        return f"{SPECS[self.type]['prefix']}-{domain_hash(self.domain, self._fields_bytes)}"

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(
            {"type": self.type, "schema_version": self.schema_version, "fields": self.fields}
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VEPObject":
        doc = strict_loads(data)
        if not isinstance(doc, dict) or set(doc) != {"type", "schema_version", "fields"}:
            raise SchemaError("malformed object envelope")
        if isinstance(doc["schema_version"], bool) or not isinstance(doc["schema_version"], int):
            raise SchemaError("schema_version must be an integer")
        obj = cls.create(doc["type"], doc["fields"], doc["schema_version"])
        if obj.canonical_bytes() != data:
            raise SchemaError("object bytes are not in canonical form")
        return obj

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)
