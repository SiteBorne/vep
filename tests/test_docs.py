"""Documentation traceability: registries must match the code they describe."""
import re
import subprocess
import sys
import unittest
from pathlib import Path

from vep import cli, errors, objects, policies

ROOT = Path(__file__).resolve().parents[1]


class DocsTests(unittest.TestCase):
    def test_variable_registry_is_current(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_variables.py"), "--check"])
        self.assertEqual(r.returncode, 0, "run: python scripts/gen_variables.py")

    def test_registry_covers_every_schema_field_policy_key_and_exit_code(self):
        text = (ROOT / "docs" / "VARIABLES.md").read_text()
        for t, spec in objects.SPECS.items():
            for f in spec["fields"]:
                self.assertIn(f"{t}.{f}", text)
        for k in policies.DEFAULT_LIMITS:
            self.assertIn(f"limits.{k}", text)
        for kind, fields in policies.EVALUATOR_GRAMMAR.items():
            for f in fields - {"kind"}:
                self.assertIn(f"evaluator.{f}", text)
        for name, cls in vars(errors).items():
            if isinstance(cls, type) and issubclass(cls, errors.VepError) and cls is not errors.VepError:
                self.assertRegex(text, rf"\b{cls.exit_code}\b")

    def test_invariant_registry_references_existing_tests(self):
        text = (ROOT / "docs" / "INVARIANTS.md").read_text()
        refs = re.findall(r"`(tests/\w+\.py)::(\w+)\.(\w+)`", text)
        self.assertGreater(len(refs), 30)
        for path, cls, meth in refs:
            src = (ROOT / path).read_text()
            self.assertRegex(src, rf"class {cls}\b", f"{path}::{cls}")
            self.assertRegex(src, rf"def {meth}\(", f"{path}::{cls}.{meth}")

    def test_every_cli_subcommand_is_documented(self):
        readme = (ROOT / "README.md").read_text()
        for name in ("init", "status", "snapshot", "diff", "objective", "candidate", "evaluate", "verify", "budget",
                     "tokens", "context", "route", "cache", "audit", "isolation", "simulate"):
            self.assertIn(name, cli.build_parser().format_help())
        for name in ("init", "objective", "candidate", "evaluate", "certify", "verify", "route", "cache", "simulate", "isolation"):
            self.assertIn(f"vep {name}", readme)

    def test_failure_matrix_has_a_test_for_every_failure_id(self):
        src = (ROOT / "tests" / "test_adversarial.py").read_text()
        for i in list(range(1, 12)) + list(range(17, 21)):
            self.assertRegex(src, rf"def test_F{i:02d}", f"F{i:02d}")
        self.assertIn("def test_F12_to_F16_", src)  # F12-F16 are exercised together through policy audits

    def test_docs_never_claim_global_optimality(self):
        for p in (ROOT / "README.md", *(ROOT / "docs").glob("*.md")):
            self.assertNotIn("is globally optimal", p.read_text().lower(), p.name)


if __name__ == "__main__":
    unittest.main()
