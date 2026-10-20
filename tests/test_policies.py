import unittest

from vep import policies
from vep.errors import SchemaError
from tests.helpers import VepTestCase


class PolicyTests(VepTestCase):
    def test_evaluator_grammar_rejects_free_form_commands(self):
        for bad in ({"kind": "shell", "command": "echo ok"},
                    {"kind": "unittest", "command": "rm -rf /"},
                    {"kind": "unittest", "pattern": "$(id)"},
                    {"kind": "unittest", "pattern": "a b"},
                    {"kind": "unittest", "start_dir": "../x"},
                    {"kind": "unittest", "min_tests": 0},
                    {"kind": "pytest", "targets": []},
                    {"kind": "unittest", "import_roots": []},
                    "pytest -x"):
            with self.assertRaises(SchemaError, msg=str(bad)):
                policies.validate_evaluator(bad)
        policies.validate_evaluator({"kind": "unittest", "start_dir": "tests", "pattern": "test*.py"})

    def test_policy_freezes_required_tests_by_digest(self):
        env = self.env()
        self.assertEqual(list(env.policy["required_tests"]), ["tests/test_arithmetic.py"])
        self.assertEqual(env.policy["required_tests"]["tests/test_arithmetic.py"],
                         [e for e in env.base["entries"] if e["path"] == "tests/test_arithmetic.py"][0]["digest"])

    def test_policy_identity_changes_with_any_field(self):
        a = self.env()
        self.tmp = self.tmp / "second"; self.tmp.mkdir()
        b = self.env(limits={"timeout_s": 5})
        self.assertNotEqual(a.policy.id, b.policy.id)

    def test_protected_patterns(self):
        env = self.env()
        base = env.base
        for path in ("conftest.py", "tests/conftest.py", "pytest.ini", "setup.cfg", "pyproject.toml", "x/y/sitecustomize.py", "a.pth"):
            cid = env.candidate({path: "x\n"})
            snap = env.ws.get_object(env.ws.get_object(cid, "Candidate")["snapshot_id"], "Snapshot")
            v = policies.check_candidate(env.policy, base, snap)
            self.assertTrue(any(x.startswith("PROTECTED_PATH_CHANGED") for x in v), path)

    def test_benign_change_has_no_violations(self):
        env = self.env()
        cid = env.candidate({"arithmetic.py": "def add(a, b):\n    return b + a\n", "extra.py": "X = 1\n"})
        snap = env.ws.get_object(env.ws.get_object(cid, "Candidate")["snapshot_id"], "Snapshot")
        self.assertEqual(policies.check_candidate(env.policy, env.base, snap), [])

    def test_runner_shadowing_detected(self):
        env = self.env()
        for path in ("unittest.py", "json.py", "unittest/__init__.py", "tests/os.py", "pytest.py"):
            cid = env.candidate({path: "x = 1\n"})
            snap = env.ws.get_object(env.ws.get_object(cid, "Candidate")["snapshot_id"], "Snapshot")
            v = policies.check_candidate(env.policy, env.base, snap)
            self.assertTrue(any(x.startswith("RUNNER_SHADOWING") for x in v), path)

    def test_nested_module_with_stdlib_name_is_not_shadowing(self):
        env = self.env()
        cid = env.candidate({"pkg/json.py": "x = 1\n"})
        snap = env.ws.get_object(env.ws.get_object(cid, "Candidate")["snapshot_id"], "Snapshot")
        self.assertEqual(policies.check_candidate(env.policy, env.base, snap), [])


if __name__ == "__main__":
    unittest.main()


class AllowModuleNamesTests(unittest.TestCase):
    """A project whose own package is named like a runner dependency (VEP's `vep`) can opt in explicitly."""

    def test_allowlist_exempts_only_listed_runner_names(self):
        ev = {"kind": "unittest", "start_dir": "tests", "import_roots": ["src", "."], "allow_module_names": ["vep"]}
        self.assertEqual(policies.shadowing_paths(ev, ["src/vep/cli.py"]), [])
        self.assertEqual(policies.shadowing_paths(ev, ["src/pytest/x.py"]), ["src/pytest/x.py"])
        self.assertEqual(policies.shadowing_paths(ev, ["src/os/x.py"]), ["src/os/x.py"])
        self.assertEqual(policies.shadowing_paths({**ev, "allow_module_names": []}, ["src/vep/cli.py"]), ["src/vep/cli.py"])

    def test_stdlib_names_and_other_evaluators_cannot_use_the_allowlist(self):
        base = {"kind": "unittest", "import_roots": ["."]}
        for bad in (["os"], ["json"], "vep", [1]):
            with self.assertRaises(SchemaError):
                policies.validate_evaluator({**base, "allow_module_names": bad})
        with self.assertRaises(SchemaError):
            policies.validate_evaluator({"kind": "pytest", "targets": ["tests"], "allow_module_names": ["vep"]})


class RequiredExcludeTests(VepTestCase):
    SECOND = "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_x(self):\n        self.assertTrue(True)\n"

    def test_exclusion_is_explicit_and_validated(self):
        from tests.helpers import BASE_FILES
        from vep.policies import make_policy
        e = self.env(files={**BASE_FILES, "tests/test_second.py": self.SECOND})
        full = make_policy(e.ws, e.base, name="full")
        self.assertEqual(set(full["required_tests"]), {"tests/test_arithmetic.py", "tests/test_second.py"})
        ex = make_policy(e.ws, e.base, name="ex", required_exclude=["tests/test_second.py"])
        self.assertEqual(set(ex["required_tests"]), {"tests/test_arithmetic.py"})
        self.assertNotEqual(ex.id, full.id)  # the exclusion is part of the policy identity
        with self.assertRaises(SchemaError):
            make_policy(e.ws, e.base, name="bad", required_exclude=["tests/nope.py"])
        with self.assertRaises(SchemaError):  # cannot exclude everything
            make_policy(e.ws, e.base, name="none", required_exclude=list(full["required_tests"]))
