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
