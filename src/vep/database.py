"""SQLite persistence: transactional state, with structural triggers for key invariants."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS objects(id TEXT PRIMARY KEY, type TEXT NOT NULL, cas_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS candidates(
  id TEXT PRIMARY KEY, objective_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PROPOSED','POLICY_CHECKED','BUDGET_RESERVED','EVALUATING','EVIDENCE_READY','CERTIFIED','REJECTED')),
  version INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS transitions(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id TEXT NOT NULL,
  from_status TEXT, to_status TEXT NOT NULL, to_version INTEGER NOT NULL,
  actor TEXT NOT NULL, reason TEXT NOT NULL, proof_id TEXT, at TEXT NOT NULL,
  UNIQUE(candidate_id, to_version));
CREATE TABLE IF NOT EXISTS evidence(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, policy_id TEXT NOT NULL, action_id TEXT NOT NULL,
  verdict TEXT NOT NULL, envelope_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS certificates(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL UNIQUE, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, policy_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
  envelope_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS action_cache(action_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trusted_keys(
  key_id TEXT PRIMARY KEY, public_key_hex TEXT NOT NULL, created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS accounts(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('organization','project','objective','candidate','operation')),
  parent_id TEXT REFERENCES accounts(id), limit_micro INTEGER NOT NULL CHECK(limit_micro >= 0));
CREATE TABLE IF NOT EXISTS reservations(
  key TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
  amount_micro INTEGER NOT NULL CHECK(amount_micro > 0),
  state TEXT NOT NULL CHECK(state IN ('RESERVED','SETTLED','RELEASED','UNCERTAIN')),
  actual_micro INTEGER, settle_key TEXT, overrun_micro INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS reservation_scope(
  reservation_key TEXT NOT NULL REFERENCES reservations(key), account_id TEXT NOT NULL REFERENCES accounts(id),
  PRIMARY KEY(reservation_key, account_id));
CREATE TABLE IF NOT EXISTS ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL, reservation_key TEXT,
  event TEXT NOT NULL, amount_micro INTEGER NOT NULL, detail TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS token_receipts(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, attempt INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE, cost_micro_usd TEXT NOT NULL, cas_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS git_links(
  snapshot_id TEXT NOT NULL, commit_id TEXT NOT NULL, dirty INTEGER NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(snapshot_id, commit_id, dirty));

CREATE TRIGGER IF NOT EXISTS transitions_immutable_u BEFORE UPDATE ON transitions
BEGIN SELECT RAISE(ABORT,'transitions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS transitions_immutable_d BEFORE DELETE ON transitions
BEGIN SELECT RAISE(ABORT,'transitions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_immutable_u BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_immutable_d BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_immutable_u BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT,'evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS cert_immutable_u BEFORE UPDATE ON certificates
BEGIN SELECT RAISE(ABORT,'certificates are immutable'); END;
CREATE TRIGGER IF NOT EXISTS cand_certified_guard BEFORE UPDATE OF status ON candidates
WHEN NEW.status='CERTIFIED' AND NOT EXISTS
  (SELECT 1 FROM certificates c WHERE c.candidate_id=NEW.id AND c.snapshot_id=NEW.snapshot_id AND c.objective_id=NEW.objective_id)
BEGIN SELECT RAISE(ABORT,'CERTIFIED requires a certificate bound to the candidate snapshot'); END;
CREATE TRIGGER IF NOT EXISTS cand_evidence_guard BEFORE UPDATE OF status ON candidates
WHEN NEW.status='EVIDENCE_READY' AND NOT EXISTS
  (SELECT 1 FROM evidence e WHERE e.candidate_id=NEW.id AND e.snapshot_id=NEW.snapshot_id AND e.verdict='PASS')
BEGIN SELECT RAISE(ABORT,'EVIDENCE_READY requires PASS evidence bound to the candidate snapshot'); END;
CREATE TRIGGER IF NOT EXISTS cand_identity_guard BEFORE UPDATE OF id, objective_id, snapshot_id ON candidates
BEGIN SELECT RAISE(ABORT,'candidate identity is immutable'); END;
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
        finally:
            conn.close()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=60, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=60000")
        return conn

    @contextmanager
    def tx(self):
        """Serialized write transaction (BEGIN IMMEDIATE); rolls back on any exception."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def read(self):
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()
