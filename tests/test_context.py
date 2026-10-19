import unittest

from vep import context
from vep.errors import ContextBudgetExceeded, SnapshotError
from tests.helpers import VepTestCase

FILES = {
    "arithmetic.py": "def add(a, b):\n    return a + b\n",
    "tests/test_arithmetic.py": "import unittest\n" + "# pad\n" * 40 + "class T(unittest.TestCase):\n    def test_a(self):\n        pass\n",
    "notes.md": "x" * 4000,
    "util.py": "def helper_function():\n    return 'needle'\n",
}


class ContextTests(VepTestCase):
    def setUp(self):
        super().setUp()
        self.e = self.env(files=FILES)

    def build(self, **kw):
        kw.setdefault("max_tokens", 10_000)
        return context.build_context(self.e.ws, self.e.base.id, self.e.policy.id, **kw)

    def test_deterministic_identity(self):
        a = self.build(requested=["arithmetic.py", "notes.md"])
        b = self.build(requested=["arithmetic.py", "notes.md"])
        self.assertEqual(a.id, b.id)

    def test_manifest_contents(self):
        m = self.build(requested=["arithmetic.py"])
        self.assertEqual(m["snapshot_id"], self.e.base.id)
        self.assertEqual(m["policy_id"], self.e.policy.id)
        paths = {e["path"]: e for e in m["entries"]}
        self.assertEqual(paths["tests/test_arithmetic.py"]["reason"], "required:policy-protected")
        self.assertTrue(paths["tests/test_arithmetic.py"]["required"])
        self.assertEqual(paths["arithmetic.py"]["reason"], "requested")
        self.assertEqual(m["total_tokens"], sum(e["tokens"] for e in m["entries"]))

    def test_optional_over_budget_is_excluded_explicitly(self):
        m = self.build(requested=["notes.md", "arithmetic.py"], max_tokens=200)
        self.assertEqual([x["path"] for x in m["excluded"]], ["notes.md"])
        self.assertEqual(m["excluded"][0]["reason"], "over_budget")

    def test_protected_requirements_are_never_truncated(self):
        with self.assertRaises(ContextBudgetExceeded):
            self.build(max_tokens=5)
        with self.assertRaises(ContextBudgetExceeded):
            self.build(required=["notes.md"], max_tokens=100)

    def test_traversal_and_unknown_paths_rejected(self):
        for bad in ("../secret", "/etc/passwd", "tests/../../x", ".vep/keys/signing.pem", "missing.py"):
            with self.assertRaises(SnapshotError, msg=bad):
                self.build(requested=[bad])

    def test_keyword_retrieval_is_deterministic_and_labeled_experimental(self):
        a = self.build(keyword_query="needle helper")
        b = self.build(keyword_query="needle helper")
        self.assertEqual(a.id, b.id)
        kw = [e for e in a["entries"] if e["reason"].startswith("keyword")]
        self.assertEqual([e["path"] for e in kw], ["util.py"])
        self.assertIn("experimental", kw[0]["reason"])

    def test_default_has_no_retrieval_beyond_explicit_paths(self):
        m = self.build()
        self.assertEqual([e["path"] for e in m["entries"]], ["tests/test_arithmetic.py"])


if __name__ == "__main__":
    unittest.main()
