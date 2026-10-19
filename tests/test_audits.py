import json
import unittest

from vep import audits
from vep.errors import CanonicalError, SchemaError
from tests.helpers import VepTestCase

AGG = {"id": "r", "file": "s.json", "rules": [
    {"type": "aggregate_all", "aggregate": "ready", "components": "parts", "component_flag": "ok"}]}


def run(doc, audit=AGG):
    return audits.audit_document(doc, audit)


class AuditTests(VepTestCase):
    def test_aggregate_consistent(self):
        self.assertEqual(run({"ready": True, "parts": {"a": {"ok": True}, "b": {"ok": True}}}), [])
        self.assertEqual(run({"ready": False, "parts": {"a": {"ok": False}}}), [])

    def test_one_passing_subsystem_does_not_imply_global_readiness(self):  # F12
        f = run({"ready": True, "parts": {"a": {"ok": True}, "b": {"ok": False}}})
        self.assertTrue(any(x.startswith("AGGREGATE_TRUE_BUT_COMPONENT_NOT_READY") for x in f))

    def test_aggregate_contradicting_components_in_both_directions(self):  # F13
        f = run({"ready": False, "parts": {"a": {"ok": True}}})
        self.assertTrue(any("AGGREGATE_FALSE_BUT_ALL" in x for x in f))

    def test_empty_components_cannot_vacuously_pass(self):
        self.assertTrue(run({"ready": True, "parts": {}}))
        self.assertTrue(run({"ready": True, "parts": []}))

    def test_truthy_strings_do_not_count_as_ready(self):
        self.assertTrue(run({"ready": True, "parts": {"a": {"ok": "yes"}}}))
        self.assertTrue(run({"ready": True, "parts": {"a": {"ok": 1}}}))
        self.assertTrue(run({"ready": "true", "parts": {"a": {"ok": True}}}))

    def test_missing_fields_fail_closed(self):
        self.assertTrue(run({"parts": {"a": {"ok": True}}}))
        self.assertTrue(run({"ready": True}))
        self.assertTrue(run({"ready": True, "parts": 5}))

    def test_missing_credentials_not_ready(self):  # F16
        a = {"id": "c", "rules": [
            {"type": "require_present", "path": "creds.present"},
            {"type": "implies", "if": {"path": "ready", "equals": True}, "then": {"path": "creds.present", "equals": True}}]}
        self.assertTrue(run({"ready": True}, a))
        self.assertTrue(run({"ready": True, "creds": {"present": False}}, a))
        self.assertEqual(run({"ready": True, "creds": {"present": True}}, a), [])
        self.assertTrue(run({"ready": False}, a))  # still flags the missing required field

    def test_fixture_backed_marked_production_rejected(self):  # F14
        a = {"id": "f", "rules": [{"type": "forbid_when", "when": {"path": "mode", "equals": "production"},
                                   "forbidden": {"path": "backend", "in": ["fixture", "mock"]}}]}
        self.assertTrue(run({"mode": "production", "backend": "fixture"}, a))
        self.assertEqual(run({"mode": "production", "backend": "postgres"}, a), [])
        self.assertEqual(run({"mode": "dev", "backend": "fixture"}, a), [])

    def test_debug_surface_in_public_api_rejected(self):  # F15
        a = {"id": "d", "rules": [{"type": "forbid_values", "path": "public.endpoints", "values": ["/debug", "/admin/mutate"]}]}
        self.assertTrue(run({"public": {"endpoints": ["/health", "/internal/debug/state"]}}, a))
        self.assertEqual(run({"public": {"endpoints": ["/health"]}}, a), [])

    def test_min_value_count(self):
        a = {"id": "m", "rules": [{"type": "min_value_count", "path": "tests", "min": 2}]}
        self.assertTrue(run({"tests": ["a"]}, a))
        self.assertEqual(run({"tests": ["a", "b"]}, a), [])

    def test_unknown_rule_type_is_an_error_not_a_pass(self):
        with self.assertRaises(SchemaError):
            run({}, {"rules": [{"type": "trust_me"}]})

    def test_malformed_rule_fails_closed(self):
        self.assertTrue(any(x.startswith("MALFORMED_RULE") for x in run({}, {"rules": [{"type": "implies"}]})))

    def test_parser_rejects_duplicate_keys_and_garbage(self):
        for bad in (b'{"a":1,"a":2}', b"{", b"\xff", b"NaN"):
            with self.assertRaises(CanonicalError):
                audits.parse_audit_json(bad)
        self.assertEqual(audits.parse_audit_json(b'{"score": 0.5}'), {"score": 0.5})

    def test_audit_runs_on_exact_snapshot_and_missing_file_fails(self):
        files = {"s.json": json.dumps({"ready": True, "parts": {"a": {"ok": False}}}),
                 "arithmetic.py": "x=1\n", "tests/test_a.py": "import unittest\n"}
        e = self.env(files=files, audits=[AGG])
        res = audits.run_audits_on_snapshot(e.ws, e.base, e.policy["audits"])
        self.assertTrue(res["r"])
        res = audits.run_audits_on_snapshot(e.ws, e.base, [{**AGG, "file": "absent.json"}])
        self.assertTrue(res["r"][0].startswith("AUDIT_FILE_MISSING"))

    def test_policy_audit_blocks_evaluation_before_execution(self):
        files = {"s.json": json.dumps({"ready": True, "parts": {"a": {"ok": True}}}),
                 "arithmetic.py": "x=1\n",
                 "tests/test_a.py": "import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        pass\n"}
        e = self.env(files=files, audits=[AGG])
        good = e.candidate({"new.py": "x=2\n"})
        self.assertEqual(e.evaluate(good)["verdict"], "PASS")
        bad = e.candidate({"s.json": json.dumps({"ready": True, "parts": {"a": {"ok": False}}})})
        from vep.errors import PolicyViolation
        with self.assertRaises(PolicyViolation):
            e.evaluate(bad)
        from vep import candidates
        self.assertEqual(candidates.get_state(e.ws, bad)["status"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
