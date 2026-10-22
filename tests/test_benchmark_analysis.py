"""The benchmark extraction is reproducible, complete and internally consistent, and the validator catches tampering and mislabelling."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
A = ROOT / "benchmarks" / "analysis"
sys.path.insert(0, str(A))
import validate as V  # noqa: E402


def run(*a):
    return subprocess.run([sys.executable, *a], capture_output=True, text=True, cwd=ROOT)


class AnalysisTests(unittest.TestCase):
    def test_dataset_validates_and_regenerates_byte_identically(self):
        self.assertEqual(V.validate(), [])
        self.assertEqual(run(str(A / "extract.py"), "--check").returncode, 0)
        self.assertEqual(run(str(A / "render_baseline.py"), "--check").returncode, 0)

    def test_extraction_is_identical_in_a_shallow_clean_checkout(self):
        """Regression for the hosted failure: commit-derived provenance used to make `--check` fail in GitHub's shallow checkout. The content dataset must reproduce
        byte-for-byte from the committed files alone, and history coverage must still be verified."""
        with tempfile.TemporaryDirectory() as t:
            r = subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{ROOT}", t], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(subprocess.run(["git", "-C", t, "rev-parse", "--is-shallow-repository"], capture_output=True, text=True).stdout.strip(), "true")
            for cmd in ("extract.py", "validate.py", "render_baseline.py"):
                args = [sys.executable, str(Path(t) / "benchmarks/analysis" / cmd)] + (["--check"] if cmd != "validate.py" else [])
                p = subprocess.run(args, capture_output=True, text=True, cwd=t)
                self.assertEqual(p.returncode, 0, f"{cmd}: {p.stdout}{p.stderr}")

    def test_extraction_is_independent_of_cwd_environment_and_repeats_without_touching_tracked_files(self):
        before = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True).stdout
        for cwd, env in ((ROOT, {}), (Path(tempfile.gettempdir()), {"TZ": "Pacific/Auckland", "LC_ALL": "C", "PYTHONHASHSEED": "7"})):
            p = subprocess.run([sys.executable, str(A / "extract.py"), "--check"], capture_output=True, text=True, cwd=cwd, env={**__import__("os").environ, **env})
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"], capture_output=True, text=True).stdout, before)

    def test_history_ledger_is_verified_against_git_when_history_exists(self):
        if subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True).stdout.strip() == "true":
            self.skipTest("history is not available in a shallow clone; the shallow test above covers coverage")
        import extract as E
        doc = json.loads((A / "source-history.json").read_text())
        self.assertTrue(all(e["last_commit"] for e in doc["entries"]))
        good = E.check_history(json.loads((A / "master-dataset.json").read_text())["sources"])
        self.assertEqual(good, [])
        forged = copy.deepcopy(doc)
        forged["entries"][0]["last_commit"] = "0" * 40
        orig = E.HISTORY
        with tempfile.TemporaryDirectory() as t:
            E.HISTORY = Path(t) / "h.json"; E.HISTORY.write_text(json.dumps(forged))
            try:
                self.assertTrue(E.check_history(json.loads((A / "master-dataset.json").read_text())["sources"]))
            finally:
                E.HISTORY = orig

    def test_every_tracked_benchmark_artifact_is_inventoried(self):
        self.assertEqual(V.tracked_benchmark_files() - {s["path"] for s in json.loads((A / "master-dataset.json").read_text())["sources"]}, set())

    def test_cohorts_and_assurance_levels_are_never_merged(self):
        d = json.loads((A / "master-dataset.json").read_text())
        for key in d["aggregates_by_cohort"]:
            self.assertEqual(len(key.split("|")), 3)  # cohort|project|scenario
        self.assertEqual({o["assurance"] for o in d["observations"] if o["classification"] == "SYNTHETIC"}, {"SIMULATED"})
        self.assertTrue(all(c.get("assurance_note") for c in d["comparisons"]))
        hits = [o for o in d["observations"] if o["assurance"] == "BUILD_CACHE_HIT_NO_CERTIFICATE"]
        self.assertTrue(hits and all(o["cache_eligibility"] != "n/a" for o in hits))

    def test_validator_detects_tampering_and_mislabelling(self):
        d = json.loads((A / "master-dataset.json").read_text())
        def problems(mut):
            x = copy.deepcopy(d); mut(x)
            with tempfile.TemporaryDirectory() as t:
                p = Path(t) / "m.json"; p.write_text(json.dumps(x)); return V.validate(p)
        self.assertTrue(problems(lambda x: x["sources"][0].__setitem__("sha256", "0" * 64)))
        def bump(x):
            o = next(o for o in x["observations"] if o.get("samples") and "mean" in o["stats"]); o["stats"]["mean"] *= 2
        self.assertTrue(problems(bump))
        def mislabel(x):
            o = next(o for o in x["observations"] if o["classification"] == "SYNTHETIC"); o["assurance"] = "VEP_PROTECTED_FRESH_CERTIFICATE"
        self.assertTrue(problems(mislabel))
        def drop(x):
            x["sources"] = [s for s in x["sources"] if "hosted-linux/paired-pyflakes" not in s["path"]]
        self.assertTrue(problems(drop))

    def test_invalid_environment_runs_are_not_presented_as_measured(self):
        d = json.loads((A / "master-dataset.json").read_text())
        inval = {s["path"] for s in d["sources"] if s["classification"] == "INVALID_ENVIRONMENT"}
        self.assertIn("benchmarks/results/paired-pyflakes.json", inval)
        self.assertTrue(all(o["classification"] == "INVALID_ENVIRONMENT" for o in d["observations"] if o["source_path"] in inval))


if __name__ == "__main__":
    unittest.main()
