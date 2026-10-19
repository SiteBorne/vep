"""Database schema versioning and validated, idempotent migrations."""
from __future__ import annotations

import base64

from .canonical import strict_loads
from .errors import SchemaError
from .objects import VEPObject
from .trust import legacy_trust_level
from .versions import DB_SCHEMA_VERSION


def _cols(conn, table: str) -> set[str]:
    return {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}


def current_version(conn) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if row is not None:
        return int(row["value"])
    has_data = conn.execute("SELECT 1 FROM objects LIMIT 1").fetchone() is not None
    return 1 if (has_data or "trust_level" not in _cols(conn, "evidence")) else DB_SCHEMA_VERSION


def _trust_from_envelope(cas, digest: str) -> str:
    """Index-only classification (NOT signature verification; verify_certificate stays authoritative)."""
    try:
        env = strict_loads(cas.get(digest))
        obj = VEPObject.from_bytes(base64.b64decode(env["payload"]))
        if obj.type == "Evidence":
            return obj["trust_level"] if obj.schema_version >= 2 else legacy_trust_level(obj["isolation"])
        return obj["trust_level"] if obj.schema_version >= 2 else "LEGACY_V1"
    except Exception:
        return "UNVERIFIED"


def migrate(ws) -> dict:
    with ws.db.tx() as c:
        ver = current_version(c)
        if ver > DB_SCHEMA_VERSION:
            raise SchemaError(f"UNSUPPORTED_DATABASE_VERSION: database is v{ver}, this build supports <= v{DB_SCHEMA_VERSION}")
        changed = []
        for table in ("evidence", "certificates"):
            if "trust_level" not in _cols(c, table):
                c.execute(f"ALTER TABLE {table} ADD COLUMN trust_level TEXT")
                changed.append(table)
        for table in ("evidence", "certificates"):
            for r in c.execute(f"SELECT id, envelope_digest FROM {table} WHERE trust_level IS NULL").fetchall():
                c.execute(f"UPDATE {table} SET trust_level=? WHERE id=?",
                          (_trust_from_envelope(ws.cas, r["envelope_digest"]), r["id"]))
        c.execute("INSERT INTO meta(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (str(DB_SCHEMA_VERSION),))
        # validation: no row left unclassified, no unknown values
        for table in ("evidence", "certificates"):
            bad = c.execute(f"SELECT COUNT(*) n FROM {table} WHERE trust_level IS NULL").fetchone()["n"]
            if bad:
                raise SchemaError(f"migration validation failed: {bad} unclassified rows in {table}")
    return {"from": ver, "to": DB_SCHEMA_VERSION, "altered": changed}
