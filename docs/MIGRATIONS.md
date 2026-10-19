# Migrations

## 0.3.0 → 0.4.0a1

**Database (schema 1 → 2), automatic and idempotent.** Opening a workspace runs `vep.migrations.migrate`, inside one `BEGIN IMMEDIATE` transaction:
1. adds `trust_level` to `evidence` and `certificates` when missing;
2. classifies every existing row **explicitly** by decoding its envelope (index only; `vep verify` remains the authority): schema-v2 → the signed value; schema-v1 evidence → `TRUSTED_LOCAL` if it says `NONE_TRUSTED_LOCAL`, otherwise `UNVERIFIED`; schema-v1 certificate → `LEGACY_V1`; undecodable → `UNVERIFIED`;
3. replaces the immutability triggers so that the *only* permitted update is that one-time fill of a NULL `trust_level`;
4. validates that no row is left unclassified, then stamps `meta.schema_version = 2`.
A database stamped with a newer version is refused (`UNSUPPORTED_DATABASE_VERSION`). **Back up `.vep/` before upgrading** — there is no downgrade path (a 0.3.0 build will open the file but does not know the new column; do not mix).

**Objects.** Nothing is rewritten. v1 `Evidence`/`Certificate` remain in the CAS and decode as before. New evaluations produce v2 objects.

**What you may need to do.**
* Re-run `vep evaluate` + `vep certify` for candidates that are `EVIDENCE_READY` under 0.3.0 and not yet certified (v1 evidence is not certifiable).
* Existing certificates: `vep verify --certificate … --historical` keeps working; output shows `legacy_schema: true` and `trust_level: TRUSTED_LOCAL`.
* Existing workspaces keep their old `.vep` directory mode; run `chmod 700 .vep .vep/keys` (new workspaces do it automatically).

**Validation performed in the test-suite:** `tests/test_compat.py` builds a database with the exact frozen 0.3.0 layout (`tests/fixtures/schema_v030.sql`), inserts legacy rows, opens it with the new code, and checks classification, idempotency and refusal of future versions.

## Future migrations
Each schema change adds a numbered step to `migrations.py`, a frozen fixture of the previous layout, and a test that migrates it. Skipping versions is allowed only if every step is idempotent.
