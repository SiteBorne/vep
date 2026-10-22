"""The readiness-profile engine: no umbrella status, no inheritance, nothing unverified counts as ready."""
import importlib.util
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("profile_check", ROOT / "scripts" / "profile_check.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)


def all_pass():
    return {r: (pc.PASS, "ok") for reqs in pc.PROFILES.values() for r in reqs}


class ProfileEngineTests(unittest.TestCase):
    def test_all_prerequisites_passing_makes_every_gate_yes(self):
        self.assertEqual({v["ready"] for v in pc.evaluate_profiles(all_pass()).values()}, {"YES"})

    def test_a_failure_blocks_only_the_gates_that_list_it_or_explicitly_depend_on_them(self):
        r = all_pass(); r["claude_live_tool_use"] = (pc.UNVERIFIED, "not run")
        out = pc.evaluate_profiles(r)
        no = {k for k, v in out.items() if v["ready"] == "NO"}
        self.assertEqual(no, {"CLAUDE_LIVE_E2E_READY", "FULL_SERVICE_PRODUCTION_READY"})  # the release candidate does not depend on the live run
        self.assertIn("profile CLAUDE_LIVE_E2E_READY", out["FULL_SERVICE_PRODUCTION_READY"]["blocking"])

    def test_composite_gates_cannot_exceed_their_weakest_component(self):
        r = all_pass(); r["tests_a2a"] = (pc.FAIL, "x")
        out = pc.evaluate_profiles(r)
        self.assertEqual(out["A2A_LOOPBACK_READY"]["ready"], "NO")
        for g in ("RELEASE_CANDIDATE_READY", "ANTHROPIC_TECHNICAL_PACKAGE_READY", "FULL_SERVICE_PRODUCTION_READY"):
            self.assertEqual(out[g]["ready"], "NO", g)
        self.assertEqual(out["CORE_PROTOCOL_PRODUCTION_READY"]["ready"], "YES")  # unrelated gates keep their own verdict

    def test_unverified_and_missing_checks_are_never_ready(self):
        r = all_pass(); r["node_vectors"] = (pc.UNVERIFIED, "node missing"); del r["tests_a2a"]
        out = pc.evaluate_profiles(r)
        self.assertEqual(out["CORE_PROTOCOL_CONFORMANT"]["ready"], "NO")
        self.assertIn("tests_a2a", out["A2A_LOOPBACK_READY"]["blocking"])

    def test_the_sixteen_requested_gates_exist_and_there_is_no_umbrella_name(self):
        want = {"CORE_PROTOCOL_CONFORMANT", "CORE_PROTOCOL_PRODUCTION_READY", "REFERENCE_IMPLEMENTATION_READY", "MCP_STDIO_READY", "A2A_LOOPBACK_READY",
                "CLAUDE_PACKAGE_READY", "CLAUDE_LIVE_E2E_READY", "PLUGIN_DIRECTORY_PRECHECK_READY", "PLUGIN_PORTAL_VALIDATED", "RELEASE_CANDIDATE_READY",
                "RELEASE_PUBLISHED", "ANTHROPIC_TECHNICAL_PACKAGE_READY", "ANTHROPIC_DIRECTORY_SUBMISSION_READY", "UNTRUSTED_EXECUTION_READY",
                "EXTERNAL_SECURITY_REVIEW_COMPLETE", "FULL_SERVICE_PRODUCTION_READY"}
        self.assertEqual(set(pc.PROFILES), want)
        self.assertNotIn("PRODUCTION_READY", pc.PROFILES)

    def test_every_prerequisite_has_a_check_implementation(self):
        text = (ROOT / "scripts" / "profile_check.py").read_text()
        implemented = set(re.findall(r'R\["(\w+)"\]', text)) | {"claude_plugin_validate", "claude_client_discovery", "external_security_review", "escape_testing"}
        needed = {r for reqs in pc.PROFILES.values() for r in reqs}
        self.assertEqual(needed - implemented, set())

    def test_directory_and_full_service_gates_stay_closed_without_portal_report_release_and_review(self):
        r = all_pass()
        for k in ("plugin_portal_report", "release_published_and_verified", "external_security_review"):
            r[k] = (pc.UNVERIFIED, "not done")
        out = pc.evaluate_profiles(r)
        self.assertEqual(out["ANTHROPIC_DIRECTORY_SUBMISSION_READY"]["ready"], "NO")
        self.assertEqual(out["FULL_SERVICE_PRODUCTION_READY"]["ready"], "NO")
        self.assertEqual(out["RELEASE_CANDIDATE_READY"]["ready"], "YES")


if __name__ == "__main__":
    unittest.main()
