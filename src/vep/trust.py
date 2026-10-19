"""Trust levels: what an evidence record does and does not establish.

* A valid signature proves that the holder of the signing key signed those bytes.
* TRUSTED_LOCAL: the evaluator ran operator-trusted code in an ordinary host subprocess. Candidate code
  shared the signer's OS authority; the result is only as trustworthy as the candidate.
* ISOLATED_VERIFIED: the evaluator ran inside an isolation boundary whose properties were *tested* (an
  attestation exists), with the signing authority outside the candidate's reach.
* UNVERIFIED: necessary evidence is absent. Never satisfies any requirement and never certifies.
"""
from __future__ import annotations

from .errors import SchemaError, VerificationFailed
from .objects import TRUST_LEVELS, VEPObject

RANK = {"UNVERIFIED": 0, "TRUSTED_LOCAL": 1, "ISOLATED_VERIFIED": 2}
assert set(RANK) == set(TRUST_LEVELS)


def legacy_trust_level(isolation: str) -> str:
    """Explicit, closed mapping for schema-v1 evidence (which predates trust levels)."""
    if isolation == "NONE_TRUSTED_LOCAL":
        return "TRUSTED_LOCAL"
    return "UNVERIFIED"  # v1 DOCKER_GVISOR claims were never backed by an attestation


def trust_level_of(evidence: VEPObject) -> str:
    if evidence.type != "Evidence":
        raise SchemaError("trust_level_of expects Evidence")
    if evidence.schema_version >= 2:
        return evidence["trust_level"]
    return legacy_trust_level(evidence["isolation"])


def satisfies(actual: str, required: str) -> bool:
    if actual not in RANK or required not in RANK:
        raise SchemaError(f"unknown trust level {actual!r}/{required!r}")
    if required == "UNVERIFIED":
        raise SchemaError("UNVERIFIED cannot be a requirement")
    return RANK[actual] >= RANK[required]


def require(actual: str, required: str) -> None:
    if not satisfies(actual, required):
        raise VerificationFailed(f"TRUST_LEVEL_INSUFFICIENT: evidence is {actual}, policy/verifier requires {required}")
