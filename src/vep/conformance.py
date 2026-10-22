"""Conformance: portable certificate bundles and the reference bundle verifier (suite 1.0).

A bundle is everything needed to check a certificate offline, with no database or CAS:

  {"bundle_version": 1,
   "trusted_keys": [{"key_id": <sha256 hex of raw public key>, "public_key_hex": <32-byte Ed25519 key hex>}],
   "certificate_envelope": <DSSE-style envelope>, "evidence_envelope": <DSSE-style envelope>,
   "expect": {"require_trust": "TRUSTED_LOCAL"|"ISOLATED_VERIFIED", "objective_id"?, "policy_id"?, "snapshot_id"?}}

`verify_bundle` returns {"valid": bool, "code": <reason code or None>, ...}. The normative description is
docs/CONFORMANCE.md; conformance/node/verify.mjs is an independent implementation of it. Check order is part
of the contract because it decides which code a multiply-broken bundle reports.
"""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import objects, trust
from .canonical import canonical_bytes, sha256_hex, strict_loads
from .errors import CanonicalError, SchemaError, VepError
from .evidence import PAYLOAD_TYPE, _pae
from .objects import VEPObject

BUNDLE_VERSION = 1
SUITE_VERSION = "1.0"
CODES = (
    "MALFORMED_BUNDLE", "UNSUPPORTED_BUNDLE_VERSION", "MALFORMED_ENVELOPE", "UNTRUSTED_KEY", "SIGNATURE_INVALID",
    "MALFORMED_PAYLOAD", "NONCANONICAL_PAYLOAD", "WRONG_TYPE", "UNSUPPORTED_SCHEMA_VERSION", "SCHEMA_INVALID",
    "EVIDENCE_DIGEST_MISMATCH", "IDENTITY_MISMATCH", "BINDING_MISMATCH", "TRUST_BINDING_MISMATCH",
    "TRUST_INSUFFICIENT", "EVIDENCE_NOT_PASSING", "EVIDENCE_SNAPSHOT_MISMATCH", "OBJECTIVE_MISMATCH",
    "POLICY_MISMATCH", "SNAPSHOT_MISMATCH")


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _b64(s: Any) -> bytes:
    if not isinstance(s, str):
        raise ValueError("not a string")
    return base64.b64decode(s, validate=True)


def _open(envelope: Any, keys: dict[str, bytes], expect_type: str) -> VEPObject:
    if not isinstance(envelope, dict) or set(envelope) != {"payloadType", "payload", "signatures"} \
            or envelope["payloadType"] != PAYLOAD_TYPE:
        raise Reject("MALFORMED_ENVELOPE")
    sigs = envelope["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict) or set(sigs[0]) != {"keyid", "sig"}:
        raise Reject("MALFORMED_ENVELOPE", "exactly one signature required")
    try:
        payload, sig, kid = _b64(envelope["payload"]), _b64(sigs[0]["sig"]), sigs[0]["keyid"]
    except (ValueError, binascii.Error):
        raise Reject("MALFORMED_ENVELOPE", "bad base64") from None
    if not isinstance(kid, str):
        raise Reject("MALFORMED_ENVELOPE")
    raw = keys.get(kid)
    if raw is None:
        raise Reject("UNTRUSTED_KEY")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, _pae(PAYLOAD_TYPE, payload))
    except (InvalidSignature, ValueError):
        raise Reject("SIGNATURE_INVALID") from None
    try:
        doc = strict_loads(payload)
    except (CanonicalError, ValueError):
        raise Reject("MALFORMED_PAYLOAD") from None
    if not isinstance(doc, dict) or set(doc) != {"type", "schema_version", "fields"} \
            or not isinstance(doc["type"], str) or isinstance(doc["schema_version"], bool) \
            or not isinstance(doc["schema_version"], int) or not isinstance(doc["fields"], dict):
        raise Reject("MALFORMED_PAYLOAD", "bad object envelope")
    if doc["type"] != expect_type:
        raise Reject("WRONG_TYPE")
    try:
        objects.spec_for(doc["type"], doc["schema_version"])
    except SchemaError:
        raise Reject("UNSUPPORTED_SCHEMA_VERSION") from None
    try:
        obj = VEPObject.create(doc["type"], doc["fields"], doc["schema_version"])
    except (SchemaError, CanonicalError):
        raise Reject("SCHEMA_INVALID") from None
    if obj.canonical_bytes() != payload:
        raise Reject("NONCANONICAL_PAYLOAD")
    return obj


def verify_bundle(bundle: Any) -> dict:
    try:
        return _verify(bundle)
    except Reject as r:
        return {"valid": False, "code": r.code, "detail": r.detail}


def _verify(bundle: Any) -> dict:
    if not isinstance(bundle, dict) or "bundle_version" not in bundle:
        raise Reject("MALFORMED_BUNDLE")
    bv = bundle["bundle_version"]
    if isinstance(bv, bool) or not isinstance(bv, int):
        raise Reject("MALFORMED_BUNDLE")
    if bv != BUNDLE_VERSION:
        raise Reject("UNSUPPORTED_BUNDLE_VERSION")
    if set(bundle) != {"bundle_version", "trusted_keys", "certificate_envelope", "evidence_envelope", "expect"}:
        raise Reject("MALFORMED_BUNDLE")
    expect, tk = bundle["expect"], bundle["trusted_keys"]
    if not isinstance(expect, dict) or expect.get("require_trust") not in ("TRUSTED_LOCAL", "ISOLATED_VERIFIED") \
            or not set(expect) <= {"require_trust", "objective_id", "policy_id", "snapshot_id"} \
            or any(not isinstance(v, str) for v in expect.values()) or not isinstance(tk, list):
        raise Reject("MALFORMED_BUNDLE")
    keys: dict[str, bytes] = {}
    for k in tk:
        if not isinstance(k, dict) or set(k) != {"key_id", "public_key_hex"} or not isinstance(k["key_id"], str) \
                or not isinstance(k["public_key_hex"], str):
            raise Reject("MALFORMED_BUNDLE")
        try:
            raw = bytes.fromhex(k["public_key_hex"])
        except ValueError:
            raise Reject("MALFORMED_BUNDLE") from None
        if len(raw) != 32 or sha256_hex(raw) != k["key_id"]:
            raise Reject("MALFORMED_BUNDLE", "key_id is not the SHA-256 of the key")
        keys[k["key_id"]] = raw
    cert = _open(bundle["certificate_envelope"], keys, "Certificate")
    ev = _open(bundle["evidence_envelope"], keys, "Evidence")
    cert_trust = cross_checks(cert, ev, bundle["evidence_envelope"], expect["require_trust"])
    for field, code in (("objective_id", "OBJECTIVE_MISMATCH"), ("policy_id", "POLICY_MISMATCH"),
                        ("snapshot_id", "SNAPSHOT_MISMATCH")):
        if field in expect and expect[field] != cert[field]:
            raise Reject(code)
    return {"valid": True, "code": None, "trust_level": cert_trust, "certificate_id": cert.id,
            "snapshot_id": cert["snapshot_id"], "assurance": "INTERNAL_CONSISTENCY_ONLY"}


def cross_checks(cert: VEPObject, ev: VEPObject, ev_envelope: Any, require_trust: str) -> str:
    """Bindings between a certificate and its evidence (shared by the v1 internal check and the authorized check). Returns the certificate trust level."""
    if sha256_hex(canonical_bytes(ev_envelope)) != cert["evidence_envelope_digest"]:
        raise Reject("EVIDENCE_DIGEST_MISMATCH")
    if ev.id != cert["evidence_id"]:
        raise Reject("IDENTITY_MISMATCH")
    for k in ("candidate_id", "objective_id", "snapshot_id", "policy_id"):
        if ev[k] != cert[k]:
            raise Reject("BINDING_MISMATCH", k)
    ev_trust = trust.trust_level_of(ev)
    if cert.schema_version >= 2:
        if cert["trust_level"] != ev_trust or cert["evaluator_id"] != ev["evaluator_id"]:
            raise Reject("TRUST_BINDING_MISMATCH")
        cert_trust = cert["trust_level"]
    else:
        cert_trust = ev_trust
    if ev_trust == "UNVERIFIED" or not trust.satisfies(cert_trust, require_trust):
        raise Reject("TRUST_INSUFFICIENT")
    if ev["verdict"] != "PASS" or ev["tests_passed"] < 1 or ev["tests_skipped"] >= ev["tests_run"] or ev["tests_failed"]:
        raise Reject("EVIDENCE_NOT_PASSING")
    if ev["staged_tree_snapshot_id"] != cert["snapshot_id"]:
        raise Reject("EVIDENCE_SNAPSHOT_MISMATCH")
    return cert_trust


# ---------------------------------------------------------------- reference side of the other vector ops
def run_vector(v: dict) -> dict:
    """Execute one frozen vector with the reference implementation; returns the observed result."""
    op = v["op"]
    if op == "canonicalize":
        try:
            return {"valid": True, "output_hex": canonical_bytes(strict_loads(bytes.fromhex(v["input_hex"]))).hex()}
        except (CanonicalError, ValueError, RecursionError):
            return {"valid": False}
    if op == "domain_hash":
        from .canonical import domain_hash
        return {"digest": domain_hash(v["domain"], bytes.fromhex(v["data_hex"]))}
    if op == "object_id":
        from .canonical import domain_hash
        fb = canonical_bytes(v["fields"])
        t, sv = v["type"], v["schema_version"]
        return {"canonical_hex": canonical_bytes({"type": t, "schema_version": sv, "fields": v["fields"]}).hex(),
                "id": f"{objects.SPECS[t]['prefix']}-{domain_hash(f'vep.{t}.v{sv}', fb)}"}
    if op == "verify_bundle":
        r = verify_bundle(v["bundle"])
        return {"valid": r["valid"], "code": r["code"]}
    if op == "verify_authorized":
        from . import trustpolicy
        r = trustpolicy.verify_authorized(v["bundle"], v["trust_policy"], v["now"])
        return {"valid": r["valid"], "code": r["code"]}
    if op == "verify_derived":
        from . import trustpolicy
        r = trustpolicy.verify_derived_authorized(v["bundle"], v["trust_policy"], v["now"])
        return {"valid": r["valid"], "code": r["code"]}
    if op == "trust_policy_id":
        from . import trustpolicy
        return {"id": trustpolicy.policy_id(v["trust_policy"])}
    raise VepError(f"unknown vector op {op!r}")


def check_vector(v: dict, observed: dict) -> bool:
    return all(observed.get(k) == val for k, val in v["expect"].items())


def load_suite(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


# ---------------------------------------------------------------- export from a workspace
def export_bundle(ws, certificate_id: str, require_trust: str = "TRUSTED_LOCAL", version: int = 1) -> dict:
    """Assemble a portable bundle for a certificate issued by this workspace. Version 1 carries its issuer key and expectations (internal
    consistency only); version 2 carries only the two signed envelopes and must be verified against a relying-party trust policy."""
    from .errors import VerificationFailed
    with ws.db.read() as c:
        row = c.execute("SELECT envelope_digest FROM certificates WHERE id=?", (certificate_id,)).fetchone()
    if row is None:
        raise VerificationFailed(f"unknown certificate {certificate_id}")
    cert_env = strict_loads(ws.cas.get(row["envelope_digest"]))
    cert = VEPObject.from_bytes(base64.b64decode(cert_env["payload"]))
    ev_env = strict_loads(ws.cas.get(cert["evidence_envelope_digest"]))
    kid = cert_env["signatures"][0]["keyid"]
    with ws.db.read() as c:
        key = c.execute("SELECT public_key_hex FROM trusted_keys WHERE key_id=?", (kid,)).fetchone()
    if key is None:
        raise VerificationFailed("signing key not in the workspace registry")
    if version == 2:  # no embedded keys or expectations: only a relying party's trust policy can authorize it
        return {"bundle_version": 2, "certificate_envelope": cert_env, "evidence_envelope": ev_env}
    return {"bundle_version": BUNDLE_VERSION, "trusted_keys": [{"key_id": kid, "public_key_hex": key["public_key_hex"]}],
            "certificate_envelope": cert_env, "evidence_envelope": ev_env,
            "expect": {"require_trust": require_trust, "objective_id": cert["objective_id"],
                       "policy_id": cert["policy_id"], "snapshot_id": cert["snapshot_id"]}}
