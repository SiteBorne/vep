"""Independent version axes. Changing one does not imply changing another."""
from __future__ import annotations

PACKAGE_VERSION = "0.5.0b1"        # distribution version (PEP 440); must equal pyproject.toml
PROTOCOL_VERSION = "0.3"           # wire-level semantics: canonicalization, identity derivation, lifecycle
CANONICAL_FORMAT = "VEP-C1"        # canonical serialization rules
DB_SCHEMA_VERSION = 3              # SQLite layout (2 adds evidence/certificate trust columns; 3 adds controller jobs/job_events)
EVIDENCE_FORMAT_VERSION = 2        # Evidence/Certificate object schema generation (1 = legacy, no trust fields)
OBJECT_SCHEMA_VERSIONS = {"Evidence": 2, "Certificate": 2}  # all other types: 1; see objects.CURRENT_VERSION

EVALUATOR_NAME = "vep-local-evaluator"


def evaluator_id(trust_level: str) -> str:
    return f"{EVALUATOR_NAME}/{PACKAGE_VERSION}/{trust_level}"


def summary() -> dict:
    from . import objects
    return {"package": PACKAGE_VERSION, "protocol": PROTOCOL_VERSION, "canonical_format": CANONICAL_FORMAT,
            "database_schema": DB_SCHEMA_VERSION, "evidence_format": EVIDENCE_FORMAT_VERSION,
            "object_schema_versions": {t: objects.version_of(t) for t in objects.SPECS},
            "supported_decoding": {t: list(objects.SUPPORTED_VERSIONS.get(t, (1,))) for t in objects.SPECS}}
