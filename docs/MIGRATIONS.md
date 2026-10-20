# Migrations

## 0.4.0a1 → 0.5.0b1

**Database (schema 2 → 3), automatic and idempotent.** Opening a workspace creates the new tables with `CREATE TABLE IF NOT EXISTS` (`jobs`, `job_events`, `build_cache`, `build_log` and their append-only triggers) and stamps `meta.schema_version = 3`. No existing row is rewritten. The migration steps from schema 1 still run first for pre-0.4 databases. A database stamped newer than the build is refused. **Back up `.vep/` first**: a 0.4 build can open the file but does not know the new tables.

**Objects.** Nothing is rewritten; v1 and v2 `Evidence`/`Certificate` objects decode as before, and a published 0.4.0a1 certificate keeps verifying with the same trust classification.

**Validated by tests, not assumed:** `tests/test_migration_fixtures.py` opens frozen workspaces produced by the real earlier builds (a schema-2 workspace generated with the `v0.4.0a1` tag's code, and the 0.3.0 layout) with the new code, checks the stamped version, that every pre-existing certificate still verifies with its original trust semantics, and that the new tables are usable.

**What you may need to do.** Re-run evaluations that must benefit from the runner fix: evidence produced before it was computed with a different runner digest and is not reused.

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
