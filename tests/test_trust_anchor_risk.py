"""P0 reproduction: a fully self-consistent bundle made by an attacker verifies under the v1 internal-consistency check.

The v1 bundle carries its own trusted_keys and expect block, so its result can only mean 'internally consistent'. These tests pin
that fact (assurance label) and prove the authorized mode (relying-party trust policy) rejects the same bundle.
"""
import base64
import copy
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vep import conformance
from vep.canonical import canonical_bytes, sha256_hex
from vep.evidence import PAYLOAD_TYPE, _pae
from vep.objects import VEPObject


def h(x: str) -> str:
    return hashlib.sha256(x.encode()).hexdigest()


def attacker_bundle():
    """An attacker invents a snapshot, evidence and certificate, signs with a key they generated, and ships their own key and expectations."""
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = sha256_hex(raw)
    ids = {"cand": "cand-" + h("c"), "obj": "obj-" + h("o"), "snap": "snap-" + h("s"), "pol": "pol-" + h("p"), "act": "act-" + h("a")}

    def sign(obj):
        payload = obj.canonical_bytes()
        sig = k.sign(_pae(PAYLOAD_TYPE, payload))
        return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
                "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}
    ev = VEPObject.create("Evidence", {
        "candidate_id": ids["cand"], "objective_id": ids["obj"], "snapshot_id": ids["snap"], "policy_id": ids["pol"], "action_id": ids["act"],
        "runner_digest": h("r"), "argv": ["x"], "exit_code": 0, "verdict": "PASS", "tests_discovered": 9, "tests_run": 9, "tests_passed": 9,
        "tests_failed": 0, "tests_skipped": 0, "executed_ids_digest": h("i"), "stdout_digest": h("o1"), "stderr_digest": h("e1"),
        "staged_tree_snapshot_id": ids["snap"], "isolation": "NONE_TRUSTED_LOCAL", "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:01Z", "budget_reservation": "x", "trust_level": "TRUSTED_LOCAL",
        "evaluator_id": "attacker/1/TRUSTED_LOCAL", "execution_environment": {"kind": "fake"}}, 2)
    ev_env = sign(ev)
    cert = VEPObject.create("Certificate", {
        "candidate_id": ids["cand"], "objective_id": ids["obj"], "snapshot_id": ids["snap"], "policy_id": ids["pol"], "evidence_id": ev.id,
        "evidence_envelope_digest": sha256_hex(canonical_bytes(ev_env)), "issuer_key_id": kid, "issued_at": "2026-01-01T00:00:02Z",
        "trust_level": "TRUSTED_LOCAL", "evaluator_id": "attacker/1/TRUSTED_LOCAL"}, 2)
    v1 = {"bundle_version": 1, "trusted_keys": [{"key_id": kid, "public_key_hex": raw.hex()}], "certificate_envelope": sign(cert),
          "evidence_envelope": ev_env, "expect": {"require_trust": "TRUSTED_LOCAL", "snapshot_id": ids["snap"], "objective_id": ids["obj"], "policy_id": ids["pol"]}}
    return v1, ids, kid, raw


class TrustAnchorRiskTests(unittest.TestCase):
    def test_attacker_bundle_is_internally_consistent_and_says_so(self):
        v1, *_ = attacker_bundle()
        r = conformance.verify_bundle(v1)
        self.assertTrue(r["valid"])  # reproduced: nothing in the bundle can tell the attacker from a real issuer
        self.assertEqual(r["assurance"], "INTERNAL_CONSISTENCY_ONLY")  # the result now states what it does NOT establish

    def test_authorized_mode_rejects_the_same_forgery(self):
        from vep import trustpolicy
        v1, ids, kid, raw = attacker_bundle()
        v2 = {"bundle_version": 2, "certificate_envelope": v1["certificate_envelope"], "evidence_envelope": v1["evidence_envelope"]}
        genuine_key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        pol = trustpolicy.make_policy("relying-party", [trustpolicy.issuer(genuine_key)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=ids["snap"])
        r = trustpolicy.verify_authorized(v2, pol, "2026-06-01T00:00:00Z")
        self.assertFalse(r["valid"])
        self.assertEqual(r["code"], "UNAUTHORIZED_ISSUER")
        # even if the attacker's key is listed, their made-up evaluator identity is not authorized
        pol2 = trustpolicy.make_policy("rp2", [trustpolicy.issuer(raw)], ["vep-local-evaluator/*"], "TRUSTED_LOCAL", snapshot_id=ids["snap"])
        self.assertEqual(trustpolicy.verify_authorized(v2, pol2, "2026-06-01T00:00:00Z")["code"], "EVALUATOR_NOT_AUTHORIZED")


if __name__ == "__main__":
    unittest.main()
