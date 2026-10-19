"""Protocol/schema/database compatibility (R005, R006, R007, R026) against frozen 0.3.0 fixtures."""
import base64
import json
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from vep import certificates, trust, versions
from vep.canonical import canonical_bytes
from vep.errors import CanonicalError, SchemaError, VerificationFailed
from vep.evidence import load_signed
from vep.objects import VEPObject
from vep.workspace import Workspace
from tests.helpers import VepTestCase, src_env

FIX = Path(__file__).parent / "fixtures"
LEGACY = json.loads((FIX / "legacy_v1_objects.json").read_text())


class ObjectVersionTests(unittest.TestCase):
    def test_frozen_v1_objects_decode_with_unchanged_identity(self):
        for kind in ("evidence", "certificate"):
            raw = LEGACY[kind]["canonical"].encode()
            obj = VEPObject.from_bytes(raw)
            self.assertEqual(obj.schema_version, 1)
            self.assertEqual(obj.id, LEGACY[kind]["id"])
            self.assertEqual(obj.canonical_bytes(), raw)

    def test_legacy_evidence_trust_classification_is_explicit_and_conservative(self):
        ev = VEPObject.from_bytes(LEGACY["evidence"]["canonical"].encode())
        self.assertEqual(trust.trust_level_of(ev), "TRUSTED_LOCAL")
        claims_isolation = VEPObject.create("Evidence", {**ev.fields, "isolation": "DOCKER_GVISOR"}, schema_version=1)
        self.assertEqual(trust.trust_level_of(claims_isolation), "UNVERIFIED")  # never upgraded to verified

    def test_R005_R026_versions_are_not_interchangeable(self):
        raw = json.loads(LEGACY["evidence"]["canonical"])
        as_v2 = dict(raw, schema_version=2)
        with self.assertRaises(SchemaError):  # v1 body lacks v2 trust fields
            VEPObject.from_bytes(canonical_bytes(as_v2))
        v1 = VEPObject.from_bytes(LEGACY["evidence"]["canonical"].encode())
        v2 = VEPObject.create("Evidence", {**v1.fields, "trust_level": "TRUSTED_LOCAL", "evaluator_id": "x",
                                           "execution_environment": {}})
        self.assertNotEqual(v1.id, v2.id)
        self.assertNotEqual(v1.domain, v2.domain)
        with self.assertRaises(SchemaError):  # a v2 body is not valid as v1 (unknown fields)
            VEPObject.create("Evidence", v2.fields, schema_version=1)

    def test_R006_unknown_versions_fail_predictably(self):
        raw = json.loads(LEGACY["evidence"]["canonical"])
        for v in (0, 3, 99, -1, "1", True, None):
            with self.assertRaises(SchemaError, msg=repr(v)):
                VEPObject.from_bytes(json.dumps(dict(raw, schema_version=v)).encode())
        with self.assertRaises(CanonicalError):  # floats are never valid, including as a version
            VEPObject.from_bytes(json.dumps(dict(raw, schema_version=1.5)).encode())
        with self.assertRaisesRegex(SchemaError, "UNSUPPORTED_SCHEMA_VERSION"):
            VEPObject.from_bytes(canonical_bytes(dict(raw, schema_version=3)))
        with self.assertRaisesRegex(SchemaError, "UNSUPPORTED_SCHEMA_VERSION"):
            VEPObject.create("Observation", {}, schema_version=2)
        self.assertEqual(SchemaError.exit_code, 11)

    def test_unchanged_types_keep_their_0_3_identities(self):
        obs = {"subject": "s", "metric": "m", "value": "1.5", "unit": "x", "source": "measured",
               "observed_at": "2026-01-01T00:00:00Z"}
        self.assertEqual(VEPObject.create("Observation", obs).id,
                         "obs-c956a8b7debe5ece7f0d146b91a7a08717a824dc78ce61ddd0ebc75325458600")

    def test_version_axes_are_reported_independently(self):
        s = versions.summary()
        for k in ("package", "protocol", "canonical_format", "database_schema", "evidence_format"):
            self.assertIn(k, s)
        self.assertEqual(s["package"], __import__("vep").__version__)
        self.assertEqual(s["evidence_format"], s["object_schema_versions"]["Evidence"])


class LegacyDatabaseTests(VepTestCase):
    def legacy_root(self):
        root = self.tmp / "legacy"; (root / ".vep").mkdir(parents=True)
        con = sqlite3.connect(root / ".vep" / "vep.db")
        con.executescript((FIX / "schema_v030.sql").read_text())  # exact 0.3.0 layout, frozen
        con.close()
        return root

    @staticmethod
    def signed_with_throwaway_key(obj, key):
        from vep import evidence as evmod
        payload = obj.canonical_bytes()
        sig = key.sign(evmod._pae(evmod.PAYLOAD_TYPE, payload))
        return canonical_bytes({"payloadType": evmod.PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
                                "signatures": [{"keyid": "0" * 64, "sig": base64.b64encode(sig).decode()}]})

    def test_old_database_migrates_and_classifies_rows_explicitly(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from vep.storage import CAS
        root = self.legacy_root()
        cas, key = CAS(root / ".vep" / "cas"), Ed25519PrivateKey.generate()  # throwaway key, never stored
        fields = json.loads(LEGACY["evidence"]["canonical"])["fields"]
        ev_local = VEPObject.create("Evidence", fields, schema_version=1)
        ev_claim = VEPObject.create("Evidence", {**fields, "isolation": "DOCKER_GVISOR", "candidate_id": "cand-" + "e" * 64},
                                    schema_version=1)
        con = sqlite3.connect(root / ".vep" / "vep.db")
        for ev in (ev_local, ev_claim):
            d = cas.put(self.signed_with_throwaway_key(ev, key))
            con.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?)", (ev.id, ev["candidate_id"], ev["objective_id"],
                        ev["snapshot_id"], ev["policy_id"], ev["action_id"], ev["verdict"], d))
        con.commit(); con.close()
        ws = Workspace(root)  # opening triggers the validated migration
        with ws.db.read() as c:
            rows = {r["id"]: r["trust_level"] for r in c.execute("SELECT id, trust_level FROM evidence")}
            ver = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
        self.assertEqual(rows[ev_local.id], "TRUSTED_LOCAL")
        self.assertEqual(rows[ev_claim.id], "UNVERIFIED")  # an unattested v1 isolation claim is never promoted
        self.assertEqual(ver, str(versions.DB_SCHEMA_VERSION))
        Workspace(root)  # idempotent
        with ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 2)

    def test_database_from_the_future_is_refused(self):
        e = self.env()
        with e.ws.db.tx() as c:
            c.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        with self.assertRaisesRegex(SchemaError, "UNSUPPORTED_DATABASE_VERSION"):
            Workspace(e.root)

    def test_fresh_database_is_stamped_with_current_version(self):
        e = self.env()
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0],
                             str(versions.DB_SCHEMA_VERSION))


class LegacyCertificateTests(VepTestCase):
    V2_ONLY = ("trust_level", "evaluator_id", "execution_environment", "isolation_attestation_digest")

    def legacy_chain(self):
        """Re-express a genuine evaluation as schema-v1 objects signed by the workspace key."""
        e = self.env()
        cid = e.candidate({"extra.py": "X = 1\n"}); e.evaluate(cid)
        modern = certificates.certify(e.ws, cid)
        ev2 = load_signed(e.ws, modern["evidence_envelope_digest"], "Evidence")
        ev1 = VEPObject.create("Evidence", {k: v for k, v in ev2.fields.items() if k not in self.V2_ONLY}, schema_version=1)
        ev_env = e.ws.cas.put(e.keystore.sign(ev1))
        cert1 = VEPObject.create("Certificate", {
            **{k: v for k, v in modern.fields.items() if k not in ("trust_level", "evaluator_id")},
            "evidence_id": ev1.id, "evidence_envelope_digest": ev_env}, schema_version=1)
        env = e.ws.cas.put(e.keystore.sign(cert1))
        with e.ws.db.tx() as c:
            c.execute("INSERT INTO certificates(id,candidate_id,objective_id,snapshot_id,policy_id,evidence_id,envelope_digest,trust_level)"
                      " VALUES(?,?,?,?,?,?,?,?)", (cert1.id, "cand-" + "9" * 64, modern["objective_id"],
                      modern["snapshot_id"], modern["policy_id"], ev1.id, env, "TRUSTED_LOCAL"))
        return e, cid, ev1, cert1

    def test_R004_legacy_certificate_keeps_a_correct_explicit_classification(self):
        e, cid, ev1, cert1 = self.legacy_chain()
        r = certificates.verify_certificate(e.ws, cert1.id)
        self.assertTrue(r["legacy_schema"])
        self.assertEqual((r["trust_level"], r["evaluator_id"]), ("TRUSTED_LOCAL", "legacy-v1 (not recorded)"))
        with self.assertRaisesRegex(VerificationFailed, "TRUST_LEVEL_INSUFFICIENT"):
            certificates.verify_certificate(e.ws, cert1.id, require_trust="ISOLATED_VERIFIED")

    def test_legacy_evidence_cannot_be_newly_certified(self):
        e = self.env()
        cid = e.candidate(); e.evaluate(cid)
        with e.ws.db.read() as c:
            row = c.execute("SELECT * FROM evidence WHERE candidate_id=?", (cid,)).fetchone()
        ev = load_signed(e.ws, row["envelope_digest"], "Evidence")
        legacy = VEPObject.create("Evidence", {k: v for k, v in ev.fields.items() if k not in self.V2_ONLY}, schema_version=1)
        digest = e.ws.cas.put(e.keystore.sign(legacy))
        with e.ws.db.tx() as c:
            c.execute("DROP TRIGGER evidence_immutable_u")
            c.execute("UPDATE evidence SET id=?, envelope_digest=? WHERE id=?", (legacy.id, digest, row["id"]))
        with self.assertRaisesRegex(VerificationFailed, "cannot be certified"):
            certificates.certify(e.ws, cid)


class CliContractTests(VepTestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, "-m", "vep", *args], cwd=cwd or self.tmp, capture_output=True, text=True, env=src_env())

    def test_R007_failures_return_distinct_nonzero_exit_codes(self):
        e = self.env()
        r = self.run_cli("status", cwd=self.tmp)
        self.assertEqual(r.returncode, 1)
        r = self.run_cli("verify", "--certificate", "cert-" + "0" * 64, "--root", str(e.root))
        self.assertEqual(r.returncode, 4)
        r = self.run_cli("candidate", "show", "--id", "cand-" + "0" * 64, "--root", str(e.root))
        self.assertEqual(r.returncode, 15)
        r = self.run_cli("budget", "show", "--account", "nope", "--root", str(e.root))
        self.assertEqual(r.returncode, 5)
        self.assertEqual(self.run_cli("bogus").returncode, 2)

    def test_version_command_is_machine_readable_and_matches_package(self):
        out = json.loads(self.run_cli("version", "--json").stdout)
        self.assertEqual(out["package"], __import__("vep").__version__)
        self.assertEqual(out["database_schema"], versions.DB_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
