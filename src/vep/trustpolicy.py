"""Relying-party trust policy: AUTHORIZED verification of certificate bundles (bundle format 2).

A v1 bundle proves only internal consistency, because it carries its own keys and expectations. An authorized check needs
three things the bundle must not supply: which issuer keys the relying party trusts (with validity and revocation), which evaluator
identities it accepts, and which source snapshot it expects. Bundle format 2 therefore contains only the two signed envelopes.

Normative description: docs/CORE_PROTOCOL_SPEC.md (section "Authorized verification"). Check order is part of the contract.
"""
from __future__ import annotations

import re
from typing import Any

from . import trust
from .canonical import canonical_bytes, domain_hash, sha256_hex
from .conformance import Reject, _open, cross_checks

TRUST_POLICY_VERSION = 1
TS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
STATUSES = ("active", "retired", "compromised")
POLICY_KEYS = {"trust_policy_version", "name", "issuers", "authorized_evaluators", "require_trust", "permitted_evidence_versions",
               "permitted_certificate_versions", "allow_legacy_evidence", "expect"}
ISSUER_KEYS = {"key_id", "public_key_hex", "valid_from", "valid_until", "status", "status_effective_at"}
AUTHORIZED_CODES = (
    "MALFORMED_TRUST_POLICY", "SUBJECT_UNSPECIFIED", "UNSUPPORTED_BUNDLE_VERSION", "MALFORMED_BUNDLE", "MALFORMED_ENVELOPE", "UNAUTHORIZED_ISSUER",
    "SIGNATURE_INVALID", "MALFORMED_PAYLOAD", "NONCANONICAL_PAYLOAD", "WRONG_TYPE", "UNSUPPORTED_SCHEMA_VERSION", "SCHEMA_INVALID",
    "ISSUER_KEY_MISMATCH", "REVOKED_KEY", "KEY_NOT_YET_VALID", "KEY_EXPIRED", "ISSUED_IN_FUTURE", "EVIDENCE_VERSION_NOT_PERMITTED",
    "CERTIFICATE_VERSION_NOT_PERMITTED", "EVIDENCE_DIGEST_MISMATCH", "IDENTITY_MISMATCH", "BINDING_MISMATCH", "TRUST_BINDING_MISMATCH",
    "LEGACY_EVIDENCE_NOT_PERMITTED", "EVALUATOR_NOT_AUTHORIZED", "TRUST_INSUFFICIENT", "EVIDENCE_NOT_PASSING", "EVIDENCE_SNAPSHOT_MISMATCH",
    "OBJECTIVE_MISMATCH", "POLICY_MISMATCH", "SNAPSHOT_MISMATCH")


def issuer(raw_public_key: bytes, *, valid_from: str = "2000-01-01T00:00:00Z", valid_until: str | None = None, status: str = "active",
           status_effective_at: str | None = None) -> dict:
    return {"key_id": sha256_hex(raw_public_key), "public_key_hex": raw_public_key.hex(), "valid_from": valid_from, "valid_until": valid_until,
            "status": status, "status_effective_at": status_effective_at}


def make_policy(name: str, issuers: list[dict], authorized_evaluators: list[str], require_trust: str, *, snapshot_id: str,
                objective_id: str | None = None, policy_id: str | None = None, evidence_versions=(2,), certificate_versions=(2,),
                allow_legacy_evidence: bool = False) -> dict:
    expect = {"snapshot_id": snapshot_id, **({"objective_id": objective_id} if objective_id else {}), **({"policy_id": policy_id} if policy_id else {})}
    return {"trust_policy_version": TRUST_POLICY_VERSION, "name": name, "issuers": issuers, "authorized_evaluators": authorized_evaluators,
            "require_trust": require_trust, "permitted_evidence_versions": list(evidence_versions),
            "permitted_certificate_versions": list(certificate_versions), "allow_legacy_evidence": allow_legacy_evidence, "expect": expect}


def policy_id(policy: dict) -> str:
    """Content identity of a trust policy (domain-separated SHA-256 over its canonical form)."""
    return "tp-" + domain_hash("vep.TrustPolicy.v1", canonical_bytes(policy))


def _bad(msg: str) -> Reject:
    return Reject("MALFORMED_TRUST_POLICY", msg)


def validate_policy(p: Any) -> dict[str, dict]:
    """Returns {key_id: issuer entry with raw key bytes}. Raises Reject(MALFORMED_TRUST_POLICY / SUBJECT_UNSPECIFIED)."""
    if not isinstance(p, dict) or set(p) != POLICY_KEYS or p["trust_policy_version"] != TRUST_POLICY_VERSION or isinstance(p["trust_policy_version"], bool):
        raise _bad("shape or version")
    if not isinstance(p["name"], str) or not p["name"]:
        raise _bad("name")
    if p["require_trust"] not in ("TRUSTED_LOCAL", "ISOLATED_VERIFIED"):
        raise _bad("require_trust")
    for field in ("permitted_evidence_versions", "permitted_certificate_versions"):
        v = p[field]
        if not isinstance(v, list) or not v or any(isinstance(x, bool) or not isinstance(x, int) or x not in (1, 2) for x in v):
            raise _bad(field)
    if not isinstance(p["allow_legacy_evidence"], bool):
        raise _bad("allow_legacy_evidence")
    ev = p["authorized_evaluators"]
    if not isinstance(ev, list) or not ev or any(not isinstance(x, str) or not x for x in ev):
        raise _bad("authorized_evaluators")
    exp = p["expect"]
    if not isinstance(exp, dict) or not set(exp) <= {"snapshot_id", "objective_id", "policy_id"} or any(not isinstance(v, str) for v in exp.values()):
        raise _bad("expect")
    if "snapshot_id" not in exp:
        raise Reject("SUBJECT_UNSPECIFIED", "a relying party must state which source snapshot it expects")
    if not isinstance(p["issuers"], list) or not p["issuers"]:
        raise _bad("issuers")
    out: dict[str, dict] = {}
    for e in p["issuers"]:
        if not isinstance(e, dict) or set(e) != ISSUER_KEYS or e["status"] not in STATUSES:
            raise _bad("issuer entry")
        try:
            raw = bytes.fromhex(e["public_key_hex"])
        except (ValueError, TypeError):
            raise _bad("issuer key hex") from None
        if len(raw) != 32 or sha256_hex(raw) != e["key_id"]:
            raise _bad("issuer key_id is not the SHA-256 of the key")
        for f in ("valid_from", "valid_until", "status_effective_at"):
            if e[f] is not None and (not isinstance(e[f], str) or not TS.match(e[f])):
                raise _bad(f)
        if not isinstance(e["valid_from"], str):
            raise _bad("valid_from")
        if e["status"] == "retired" and e["status_effective_at"] is None:
            raise _bad("retired issuer needs status_effective_at")
        if e["key_id"] in out:
            raise _bad("duplicate issuer")
        out[e["key_id"]] = {**e, "raw": raw}
    return out


def _evaluator_ok(evaluator: str, patterns: list[str]) -> bool:
    return any(evaluator == pt or (pt.endswith("*") and evaluator.startswith(pt[:-1])) for pt in patterns)


def _key_ok(entry: dict, signed_at: str, now: str) -> None:
    """Key status and validity window at the signed time. A 'compromised' key is rejected for every certificate: its holder controls
    the signed timestamps, so no date can be trusted. A 'retired' key is rejected for certificates dated at or after its retirement."""
    if entry["status"] == "compromised":
        raise Reject("REVOKED_KEY", "compromised")
    if entry["status"] == "retired" and signed_at >= entry["status_effective_at"]:
        raise Reject("REVOKED_KEY", "retired")
    if signed_at < entry["valid_from"]:
        raise Reject("KEY_NOT_YET_VALID")
    if entry["valid_until"] is not None and signed_at >= entry["valid_until"]:
        raise Reject("KEY_EXPIRED")
    if signed_at > now:
        raise Reject("ISSUED_IN_FUTURE")


def verify_authorized(bundle: Any, policy: Any, now: str) -> dict:
    try:
        return _authorized(bundle, policy, now)
    except Reject as r:
        return {"valid": False, "code": r.code, "detail": r.detail}


def _authorized(bundle: Any, policy: Any, now: str) -> dict:
    if not isinstance(now, str) or not TS.match(now):
        raise Reject("MALFORMED_TRUST_POLICY", "now must be a UTC timestamp supplied by the relying party")
    issuers = validate_policy(policy)
    if not isinstance(bundle, dict) or "bundle_version" not in bundle or isinstance(bundle["bundle_version"], bool) or not isinstance(bundle["bundle_version"], int):
        raise Reject("MALFORMED_BUNDLE")
    if bundle["bundle_version"] != 2:
        raise Reject("UNSUPPORTED_BUNDLE_VERSION", "authorized verification needs bundle format 2 (no embedded keys or expectations)")
    if set(bundle) != {"bundle_version", "certificate_envelope", "evidence_envelope"}:
        raise Reject("MALFORMED_BUNDLE")
    keys = {kid: e["raw"] for kid, e in issuers.items()}

    def open_env(env, kind):
        try:
            return _open(env, keys, kind)
        except Reject as r:
            raise Reject("UNAUTHORIZED_ISSUER", r.detail) if r.code == "UNTRUSTED_KEY" else r
    cert = open_env(bundle["certificate_envelope"], "Certificate")
    ev = open_env(bundle["evidence_envelope"], "Evidence")
    cert_kid = bundle["certificate_envelope"]["signatures"][0]["keyid"]
    ev_kid = bundle["evidence_envelope"]["signatures"][0]["keyid"]
    if cert["issuer_key_id"] != cert_kid:
        raise Reject("ISSUER_KEY_MISMATCH", "certificate names a different issuer than the key that signed it")
    _key_ok(issuers[cert_kid], cert["issued_at"], now)
    _key_ok(issuers[ev_kid], ev["finished_at"], now)
    if cert.schema_version not in policy["permitted_certificate_versions"]:
        raise Reject("CERTIFICATE_VERSION_NOT_PERMITTED")
    if ev.schema_version not in policy["permitted_evidence_versions"]:
        raise Reject("EVIDENCE_VERSION_NOT_PERMITTED")
    # shared bindings run first so a mismatched pair is reported as such; trust-level sufficiency is evaluated below against the policy
    cert_trust = cross_checks(cert, ev, bundle["evidence_envelope"], "TRUSTED_LOCAL")
    if ev.schema_version < 2:
        if not policy["allow_legacy_evidence"]:
            raise Reject("LEGACY_EVIDENCE_NOT_PERMITTED")
    elif not _evaluator_ok(ev["evaluator_id"], policy["authorized_evaluators"]):
        raise Reject("EVALUATOR_NOT_AUTHORIZED", ev["evaluator_id"])
    if not trust.satisfies(cert_trust, policy["require_trust"]):
        raise Reject("TRUST_INSUFFICIENT")
    for field, code in (("objective_id", "OBJECTIVE_MISMATCH"), ("policy_id", "POLICY_MISMATCH"), ("snapshot_id", "SNAPSHOT_MISMATCH")):
        if field in policy["expect"] and policy["expect"][field] != cert[field]:
            raise Reject(code)
    return {"valid": True, "code": None, "assurance": "AUTHORIZED", "trust_policy_id": policy_id(policy), "issuer_key_id": cert_kid,
            "trust_level": cert_trust, "snapshot_id": cert["snapshot_id"], "certificate_id": cert.id}
