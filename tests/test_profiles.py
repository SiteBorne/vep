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
    def test_all_prerequisites_passing_makes_every_profile_yes(self):
        self.assertEqual({v["ready"] for v in pc.evaluate_profiles(all_pass()).values()}, {"YES"})

    def test_a_failure_blocks_only_the_profiles_that_list_it(self):
        r = all_pass(); r["claude_live_tool_use"] = (pc.UNVERIFIED, "not run")
        out = pc.evaluate_profiles(r)
        self.assertEqual(out["CLAUDE_INTEGRATION_READY"]["ready"], "NO")
        self.assertEqual({k for k, v in out.items() if v["ready"] == "NO"}, {"CLAUDE_INTEGRATION_READY"})  # nothing else inherits the gap

    def test_unverified_and_missing_checks_are_never_ready(self):
        r = all_pass(); r["node_vectors"] = (pc.UNVERIFIED, "node missing"); del r["tests_a2a"]
        out = pc.evaluate_profiles(r)
        self.assertEqual(out["CORE_PROTOCOL_CONFORMANT"]["ready"], "NO")
        self.assertEqual(out["A2A_INTEGRATION_READY"]["ready"], "NO")
        self.assertIn("tests_a2a", out["A2A_INTEGRATION_READY"]["blocking"])

    def test_there_is_no_umbrella_profile_and_every_prerequisite_has_a_check(self):
        self.assertNotIn("PRODUCTION_READY", pc.PROFILES)
        self.assertEqual(len(pc.PROFILES), 9)
        text = (ROOT / "scripts" / "profile_check.py").read_text()
        implemented = set(re.findall(r'R\["(\w+)"\]', text)) | set(re.findall(r'for k in \(("[^)]+)\)', text)[0].replace('"', "").replace(" ", "").split(",")) \
            | {"claude_plugin_validate", "claude_client_discovery"}
        needed = {r for reqs in pc.PROFILES.values() for r in reqs}
        self.assertEqual(needed - implemented, set())

    def test_the_isolation_and_untrusted_profiles_do_not_share_a_verdict(self):
        r = all_pass(); r["escape_testing"] = (pc.FAIL, "none")
        out = pc.evaluate_profiles(r)
        self.assertEqual((out["ISOLATED_EXECUTION_READY"]["ready"], out["UNTRUSTED_EXECUTION_READY"]["ready"]), ("YES", "NO"))


if __name__ == "__main__":
    unittest.main()
