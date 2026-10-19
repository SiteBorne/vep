import base64
import os
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vep import candidates, certificates, evidence
from vep.canonical import canonical_bytes, strict_loads
from vep.errors import StateError, VerificationFailed
from tests.helpers import VepTestCase


class CertificateTests(VepTestCase):
    def certified(self):
        e = self.env()
        cid = e.candidate({"extra.py": "X = 1\n"})
        e.evaluate(cid)
        cert = certificates.certify(e.ws, cid)
        return e, cid, cert

    def envelope_path(self, e, digest):
        return e.ws.cas._path(digest)

    def test_verifies_against_exact_current_source(self):
        e, cid, cert = self.certified()
        r = certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)
        self.assertIn("current source equals certified snapshot", r["checks_passed"])
        self.assertEqual(r["isolation_of_evidence"], "NONE_TRUSTED_LOCAL")

    def test_changed_source_invalidates_current_certification(self):
        e, cid, cert = self.certified()
        (e.last_dir / "extra.py").write_text("X = 2\n")
        with self.assertRaisesRegex(VerificationFailed, "SOURCE_CHANGED"):
            certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)
        # historical verification still holds: the certificate is about the old snapshot, not the new one
        self.assertTrue(certificates.verify_certificate(e.ws, cert.id))

    def test_added_file_also_changes_identity(self):
        e, cid, cert = self.certified()
        (e.last_dir / "new.py").write_text("")
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id, current_root=e.last_dir)

    def test_corrupted_evidence_object_detected(self):
        e, cid, cert = self.certified()
        p = self.envelope_path(e, cert["evidence_envelope_digest"])
        os.chmod(p, 0o644)
        data = bytearray(p.read_bytes())
        data[len(data) // 2] ^= 0x01
        p.write_bytes(bytes(data))
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id)

    def _resign_attempt(self, e, cert, mutate):
        """Alter the signed payload but keep the original signature (post-creation tampering)."""
        digest = cert["evidence_envelope_digest"]
        env = strict_loads(e.ws.cas.get(digest))
        payload = strict_loads(base64.b64decode(env["payload"]))
        mutate(payload["fields"])
        env["payload"] = base64.b64encode(canonical_bytes(payload)).decode()
        return e.ws.cas.put(canonical_bytes(env))

    def test_modified_signed_evidence_fails_verification(self):
        e, cid, cert = self.certified()
        new_digest = self._resign_attempt(e, cert, lambda f: f.__setitem__("tests_passed", 99))
        with self.assertRaisesRegex(VerificationFailed, "signature invalid"):
            evidence.load_signed(e.ws, new_digest, "Evidence")

    def test_certificate_row_swapped_to_another_certificate_fails(self):
        e, cid, cert = self.certified()
        cid2 = e.candidate({"other.py": "Y = 1\n"})
        e.evaluate(cid2)
        cert2 = certificates.certify(e.ws, cid2)
        with e.ws.db.read() as c:
            other_env = c.execute("SELECT envelope_digest FROM certificates WHERE id=?", (cert2.id,)).fetchone()[0]
        with e.ws.db.tx() as c:  # attacker with raw DB write access (triggers dropped)
            c.execute("DROP TRIGGER cert_immutable_u")
            c.execute("UPDATE certificates SET envelope_digest=? WHERE id=?", (other_env, cert.id))
        with self.assertRaisesRegex(VerificationFailed, "identity mismatch"):
            certificates.verify_certificate(e.ws, cert.id)

    def test_signature_by_untrusted_key_rejected(self):
        e, cid, cert = self.certified()
        evil = Ed25519PrivateKey.generate()
        digest = cert["evidence_envelope_digest"]
        env = strict_loads(e.ws.cas.get(digest))
        payload = base64.b64decode(env["payload"])
        raw = evil.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = evil.sign(evidence._pae(evidence.PAYLOAD_TYPE, payload))
        env["signatures"] = [{"keyid": evidence.key_id(raw), "sig": base64.b64encode(sig).decode()}]
        with self.assertRaisesRegex(VerificationFailed, "not trusted"):
            evidence.open_envelope(e.ws, canonical_bytes(env), "Evidence")

    def test_revoked_key_rejected(self):
        e, cid, cert = self.certified()
        with e.ws.db.tx() as c:
            c.execute("UPDATE trusted_keys SET revoked=1")
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, cert.id)

    def test_forged_key_id_swap_rejected(self):
        e, cid, cert = self.certified()
        env = strict_loads(e.ws.cas.get(cert["evidence_envelope_digest"]))
        env["signatures"][0]["keyid"] = "0" * 64
        with self.assertRaises(VerificationFailed):
            evidence.open_envelope(e.ws, canonical_bytes(env), "Evidence")

    def test_wrong_object_type_rejected(self):
        e, cid, cert = self.certified()
        with self.assertRaises(VerificationFailed):
            evidence.load_signed(e.ws, cert["evidence_envelope_digest"], "Certificate")

    def test_cannot_certify_without_evidence_ready(self):
        e = self.env()
        cid = e.candidate()
        with self.assertRaises(StateError):
            certificates.certify(e.ws, cid)

    def test_certificate_is_bound_to_objective_and_policy(self):
        e, cid, cert = self.certified()
        with self.assertRaisesRegex(VerificationFailed, "different objective"):
            certificates.verify_certificate(e.ws, cert.id, expect_objective_id="obj-" + "1" * 64)
        with self.assertRaisesRegex(VerificationFailed, "different policy"):
            certificates.verify_certificate(e.ws, cert.id, expect_policy_id="pol-" + "1" * 64)
        self.assertTrue(certificates.verify_certificate(
            e.ws, cert.id, expect_objective_id=e.objective.id, expect_policy_id=e.policy.id))

    def test_unknown_certificate(self):
        e = self.env()
        with self.assertRaises(VerificationFailed):
            certificates.verify_certificate(e.ws, "cert-" + "0" * 64)

    def test_private_key_is_private(self):
        e = self.env()
        mode = os.stat(e.keystore.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        os.chmod(e.keystore.path, 0o644)
        with self.assertRaises(Exception):
            e.keystore.key_id()
        os.chmod(e.keystore.path, 0o600)


if __name__ == "__main__":
    unittest.main()
