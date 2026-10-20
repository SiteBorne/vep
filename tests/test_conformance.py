"""Frozen conformance suite: reference and independent (Node) verifiers must agree on every vector."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import AUTH, VepTestCase
from vep import certificates, conformance, controller

ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "conformance" / "vectors" / "suite-1.0.json"
NODE = shutil.which("node")


class ReferenceTests(unittest.TestCase):
    def test_suite_is_frozen_and_regenerates_identically(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_conformance_vectors.py"), "--check"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_reference_agrees_with_every_vector(self):
        suite = conformance.load_suite(SUITE)
        bad = [v["id"] for v in suite["vectors"] if not conformance.check_vector(v, conformance.run_vector(v))]
        self.assertEqual(bad, [])

    def test_suite_covers_required_areas_with_negatives(self):
        suite = conformance.load_suite(SUITE)
        ops = {v["op"] for v in suite["vectors"]}
        self.assertEqual(ops, {"canonicalize", "domain_hash", "object_id", "verify_bundle"})
        codes = {v["expect"].get("code") for v in suite["vectors"] if v["op"] == "verify_bundle"}
        self.assertEqual(codes - {None}, set(conformance.CODES))  # every published reason code is exercised
        self.assertGreaterEqual(sum(1 for v in suite["vectors"] if v["op"] == "canonicalize" and not v["expect"]["valid"]), 20)

    def test_trailing_newline_ids_and_digests_are_rejected(self):  # regression found by the independent verifier work
        from vep.canonical import is_digest
        from vep.objects import is_id_of
        self.assertTrue(is_digest("a" * 64))
        self.assertFalse(is_digest("a" * 64 + "\n"))
        self.assertFalse(is_id_of("cand-" + "a" * 64 + "\n", "Candidate"))


@unittest.skipUnless(NODE, "node not installed: independent verifier NOT RUN")
class IndependentVerifierTests(VepTestCase):
    def node(self, *args):
        return subprocess.run([NODE, str(ROOT / "conformance" / "node" / "verify.mjs"), *args], capture_output=True, text=True)

    def test_node_verifier_agrees_on_every_vector(self):
        r = self.node("suite", str(SUITE))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"(\d+)/\1 vectors agree")

    def test_real_certificate_bundle_verifies_in_both_and_tamper_fails_in_both(self):
        e = self.env()
        controller.enqueue(e.ws, e.candidate({"extra.py": "X = 1\n"}))
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        bundle = conformance.export_bundle(e.ws, out["certificate_id"])
        self.assertTrue(conformance.verify_bundle(bundle)["valid"])
        p = self.tmp / "b.json"
        p.write_text(json.dumps(bundle))
        self.assertTrue(json.loads(self.node("bundle", str(p)).stdout)["valid"])
        # the workspace's own verifier agrees
        self.assertEqual(certificates.verify_certificate(e.ws, out["certificate_id"])["certificate_id"], out["certificate_id"])
        bundle["expect"]["policy_id"] = "pol-" + "0" * 64
        p.write_text(json.dumps(bundle))
        self.assertEqual(conformance.verify_bundle(bundle)["code"], "POLICY_MISMATCH")
        self.assertEqual(json.loads(self.node("bundle", str(p)).stdout)["code"], "POLICY_MISMATCH")
        bundle["expect"].pop("policy_id")
        bundle["expect"]["require_trust"] = "ISOLATED_VERIFIED"
        p.write_text(json.dumps(bundle))
        self.assertEqual(json.loads(self.node("bundle", str(p)).stdout)["code"], "TRUST_INSUFFICIENT")
