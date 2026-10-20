BEGIN TRANSACTION;
CREATE TABLE accounts(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('organization','project','objective','candidate','operation')),
  parent_id TEXT REFERENCES accounts(id), limit_micro INTEGER NOT NULL CHECK(limit_micro >= 0));
INSERT INTO "accounts" VALUES('objective:obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798','objective',NULL,1000000);
INSERT INTO "accounts" VALUES('candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','candidate','objective:obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798',1000000);
CREATE TABLE action_cache(action_id TEXT PRIMARY KEY, evidence_id TEXT NOT NULL);
INSERT INTO "action_cache" VALUES('act-86c47338de849bb1e0c6ba4347537c16c584fee95594ba3d0e39095788ee8f4b','evd-52f7bf0f78b50adcffdf6b6b20cb9b10442c3cbb1f59a4b3670cb95b577b528b');
CREATE TABLE candidates(
  id TEXT PRIMARY KEY, objective_id TEXT NOT NULL, snapshot_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PROPOSED','POLICY_CHECKED','BUDGET_RESERVED','EVALUATING','EVIDENCE_READY','CERTIFIED','REJECTED')),
  version INTEGER NOT NULL, created_at TEXT NOT NULL);
INSERT INTO "candidates" VALUES('cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798','snap-163c1fc09dd66c4d115f3584db3b952a779d2b2daa3c35827a2e5fe593612c19','CERTIFIED',5,'2026-10-20T05:37:16Z');
CREATE TABLE certificates(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL UNIQUE, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, policy_id TEXT NOT NULL, evidence_id TEXT NOT NULL,
  envelope_digest TEXT NOT NULL, trust_level TEXT);
INSERT INTO "certificates" VALUES('cert-0087a22fe065208d067c126de7dfc890e8bf18ea12232f215681ce3b17e6d7b4','cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798','snap-163c1fc09dd66c4d115f3584db3b952a779d2b2daa3c35827a2e5fe593612c19','pol-addee129b21bf6dce05ba68f93c5af6c853e67563d40da12c13f2c942f53c7f8','evd-52f7bf0f78b50adcffdf6b6b20cb9b10442c3cbb1f59a4b3670cb95b577b528b','6668b9afc077ca752e4e90fef0988a22884dedf8478462292328fdc58c061518','TRUSTED_LOCAL');
CREATE TABLE evidence(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, policy_id TEXT NOT NULL, action_id TEXT NOT NULL,
  verdict TEXT NOT NULL, envelope_digest TEXT NOT NULL, trust_level TEXT);
INSERT INTO "evidence" VALUES('evd-52f7bf0f78b50adcffdf6b6b20cb9b10442c3cbb1f59a4b3670cb95b577b528b','cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798','snap-163c1fc09dd66c4d115f3584db3b952a779d2b2daa3c35827a2e5fe593612c19','pol-addee129b21bf6dce05ba68f93c5af6c853e67563d40da12c13f2c942f53c7f8','act-86c47338de849bb1e0c6ba4347537c16c584fee95594ba3d0e39095788ee8f4b','PASS','c0ffc985e0cd0036d38e04edbd1bf8a3756aadf570ae129cf7fd7eb68ddb5aaa','TRUSTED_LOCAL');
CREATE TABLE git_links(
  snapshot_id TEXT NOT NULL, commit_id TEXT NOT NULL, dirty INTEGER NOT NULL, at TEXT NOT NULL,
  PRIMARY KEY(snapshot_id, commit_id, dirty));
CREATE TABLE ledger(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL, reservation_key TEXT,
  event TEXT NOT NULL, amount_micro INTEGER NOT NULL, detail TEXT NOT NULL, at TEXT NOT NULL);
INSERT INTO "ledger" VALUES(1,'objective:obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798',NULL,'ACCOUNT_CREATED',1000000,'objective','2026-10-20T05:37:16Z');
INSERT INTO "ledger" VALUES(2,'candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4',NULL,'ACCOUNT_CREATED',1000000,'candidate','2026-10-20T05:37:16Z');
INSERT INTO "ledger" VALUES(3,'candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','RESERVE',1000,'','2026-10-20T05:37:16Z');
INSERT INTO "ledger" VALUES(4,'candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','SETTLE',1000,'','2026-10-20T05:37:16Z');
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO "meta" VALUES('schema_version','2');
CREATE TABLE objects(id TEXT PRIMARY KEY, type TEXT NOT NULL, cas_digest TEXT NOT NULL);
INSERT INTO "objects" VALUES('snap-f12dcc15e9167ed00938c354c7b31f561517c514f1e0ba7a12cf6ded716e4f79','Snapshot','7b58fa74ba31a53f4ae354a184d4ffa70473c946c73eb9b5af6e1bcf51ec0845');
INSERT INTO "objects" VALUES('pol-addee129b21bf6dce05ba68f93c5af6c853e67563d40da12c13f2c942f53c7f8','ExecutionPolicy','c6e608c6f7ea13577bc135c7a9d9391b4e00ecb98c6a6d2231fbee17aba31bb1');
INSERT INTO "objects" VALUES('obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798','Objective','b4a8f9e369755218081be8878273d638df1a2e75ea9f6f3fb83a881cf490a4ca');
INSERT INTO "objects" VALUES('snap-163c1fc09dd66c4d115f3584db3b952a779d2b2daa3c35827a2e5fe593612c19','Snapshot','6d58c48abdb8c3f45aac15ec1fbbef3723f88e48ebadd26b5396712e29495fb9');
INSERT INTO "objects" VALUES('cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','Candidate','d40bd05a38464b6da025ea33921975f9698e8b0d5f6133169789fe86bb700b43');
INSERT INTO "objects" VALUES('act-86c47338de849bb1e0c6ba4347537c16c584fee95594ba3d0e39095788ee8f4b','Action','99b0f69be9cf1295a84c2339f6ab9e829316c2c5fbbfcacf27927d83562edef6');
INSERT INTO "objects" VALUES('evd-52f7bf0f78b50adcffdf6b6b20cb9b10442c3cbb1f59a4b3670cb95b577b528b','Evidence','a8f8003ed963770fa4f41277cab03a87db2bec660c7d7653ccdf8384d7025aed');
INSERT INTO "objects" VALUES('cert-0087a22fe065208d067c126de7dfc890e8bf18ea12232f215681ce3b17e6d7b4','Certificate','dc4ddd155ffe9ef370d75a53401e3abfe077d50e72bc8bed4a294b3a4dea5346');
CREATE TABLE reservation_scope(
  reservation_key TEXT NOT NULL REFERENCES reservations(key), account_id TEXT NOT NULL REFERENCES accounts(id),
  PRIMARY KEY(reservation_key, account_id));
INSERT INTO "reservation_scope" VALUES('eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4');
INSERT INTO "reservation_scope" VALUES('eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','objective:obj-6c827f1ef37493027c69b73798ad7114cfdea0adc986ffe17138cd4e6a31b798');
CREATE TABLE reservations(
  key TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
  amount_micro INTEGER NOT NULL CHECK(amount_micro > 0),
  state TEXT NOT NULL CHECK(state IN ('RESERVED','SETTLED','RELEASED','UNCERTAIN')),
  actual_micro INTEGER, settle_key TEXT, overrun_micro INTEGER NOT NULL DEFAULT 0);
INSERT INTO "reservations" VALUES('eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','candidate:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4',1000,'SETTLED',1000,'eval-settle:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4',0);
CREATE TABLE token_receipts(
  id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, attempt INTEGER NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE, cost_micro_usd TEXT NOT NULL, cas_digest TEXT NOT NULL);
CREATE TABLE transitions(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id TEXT NOT NULL,
  from_status TEXT, to_status TEXT NOT NULL, to_version INTEGER NOT NULL,
  actor TEXT NOT NULL, reason TEXT NOT NULL, proof_id TEXT, at TEXT NOT NULL,
  UNIQUE(candidate_id, to_version));
INSERT INTO "transitions" VALUES(1,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4',NULL,'PROPOSED',0,'fixture','registered',NULL,'2026-10-20T05:37:16Z');
INSERT INTO "transitions" VALUES(2,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','PROPOSED','POLICY_CHECKED',1,'vep-policy-checker','policy ok','pol-addee129b21bf6dce05ba68f93c5af6c853e67563d40da12c13f2c942f53c7f8','2026-10-20T05:37:16Z');
INSERT INTO "transitions" VALUES(3,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','POLICY_CHECKED','BUDGET_RESERVED',2,'vep-evaluator','budget reserved','eval:cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','2026-10-20T05:37:16Z');
INSERT INTO "transitions" VALUES(4,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','BUDGET_RESERVED','EVALUATING',3,'vep-evaluator','staging','act-86c47338de849bb1e0c6ba4347537c16c584fee95594ba3d0e39095788ee8f4b','2026-10-20T05:37:16Z');
INSERT INTO "transitions" VALUES(5,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','EVALUATING','EVIDENCE_READY',4,'vep-evaluator','evidence PASS','evd-52f7bf0f78b50adcffdf6b6b20cb9b10442c3cbb1f59a4b3670cb95b577b528b','2026-10-20T05:37:16Z');
INSERT INTO "transitions" VALUES(6,'cand-560fb5d5010df534521f1662c8f1f963b9d62b2cdab6f024c69c45040224a9c4','EVIDENCE_READY','CERTIFIED',5,'vep-certifier','certificate issued','cert-0087a22fe065208d067c126de7dfc890e8bf18ea12232f215681ce3b17e6d7b4','2026-10-20T05:37:16Z');
CREATE TABLE trusted_keys(
  key_id TEXT PRIMARY KEY, public_key_hex TEXT NOT NULL, created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
INSERT INTO "trusted_keys" VALUES('1436709f522be215ee4c8b29b94a3431531c1bc66099f95f9b74685ea790a129','bfbe92974d023a19d0e56e14e6dfc67c785a5e6375f257d3125eb81f36a8b8f9','2026-10-20T05:37:16Z',0);
CREATE TRIGGER transitions_immutable_u BEFORE UPDATE ON transitions
BEGIN SELECT RAISE(ABORT,'transitions are append-only'); END;
CREATE TRIGGER transitions_immutable_d BEFORE DELETE ON transitions
BEGIN SELECT RAISE(ABORT,'transitions are append-only'); END;
CREATE TRIGGER ledger_immutable_u BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;
CREATE TRIGGER ledger_immutable_d BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT,'ledger is append-only'); END;
CREATE TRIGGER cand_certified_guard BEFORE UPDATE OF status ON candidates
WHEN NEW.status='CERTIFIED' AND NOT EXISTS
  (SELECT 1 FROM certificates c WHERE c.candidate_id=NEW.id AND c.snapshot_id=NEW.snapshot_id AND c.objective_id=NEW.objective_id)
BEGIN SELECT RAISE(ABORT,'CERTIFIED requires a certificate bound to the candidate snapshot'); END;
CREATE TRIGGER cand_evidence_guard BEFORE UPDATE OF status ON candidates
WHEN NEW.status='EVIDENCE_READY' AND NOT EXISTS
  (SELECT 1 FROM evidence e WHERE e.candidate_id=NEW.id AND e.snapshot_id=NEW.snapshot_id AND e.verdict='PASS')
BEGIN SELECT RAISE(ABORT,'EVIDENCE_READY requires PASS evidence bound to the candidate snapshot'); END;
CREATE TRIGGER cand_identity_guard BEFORE UPDATE OF id, objective_id, snapshot_id ON candidates
BEGIN SELECT RAISE(ABORT,'candidate identity is immutable'); END;
CREATE TRIGGER evidence_immutable_u BEFORE UPDATE ON evidence
WHEN NOT (OLD.trust_level IS NULL AND NEW.trust_level IS NOT NULL AND NEW.id=OLD.id AND NEW.candidate_id=OLD.candidate_id
  AND NEW.objective_id=OLD.objective_id AND NEW.snapshot_id=OLD.snapshot_id AND NEW.policy_id=OLD.policy_id
  AND NEW.action_id=OLD.action_id AND NEW.verdict=OLD.verdict AND NEW.envelope_digest=OLD.envelope_digest)
BEGIN SELECT RAISE(ABORT,'evidence is immutable'); END;
CREATE TRIGGER cert_immutable_u BEFORE UPDATE ON certificates
WHEN NOT (OLD.trust_level IS NULL AND NEW.trust_level IS NOT NULL AND NEW.id=OLD.id AND NEW.candidate_id=OLD.candidate_id
  AND NEW.objective_id=OLD.objective_id AND NEW.snapshot_id=OLD.snapshot_id AND NEW.policy_id=OLD.policy_id
  AND NEW.evidence_id=OLD.evidence_id AND NEW.envelope_digest=OLD.envelope_digest)
BEGIN SELECT RAISE(ABORT,'certificates are immutable'); END;
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('ledger',4);
INSERT INTO "sqlite_sequence" VALUES('transitions',6);
COMMIT;
