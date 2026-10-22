"""Extract every tracked benchmark artifact into one machine-validated dataset. Deterministic: the same tracked files give byte-identical output.

    python benchmarks/analysis/extract.py            # writes master-dataset.json and benchmark-inventory.csv next to this file
    python benchmarks/analysis/extract.py --check    # exit 1 if the committed outputs differ from a fresh extraction

Nothing is averaged across hardware cohorts: every observation carries its cohort, and `aggregates` are keyed by cohort. Classification:
MEASURED (controlled, environment valid or not subject to a declared gate), SYNTHETIC (a simulation with stated assumptions), HISTORICAL (superseded
run kept for the record), INVALID_ENVIRONMENT (the run's own declared environment criteria were not met), PROPOSED (a plan, no data).
Assurance levels are never merged: a build-cache hit, a derived attestation, heuristic test selection and a freshly issued certificate are distinct.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent
CLASSES = ("MEASURED", "SYNTHETIC", "HISTORICAL", "PROPOSED", "INVALID_ENVIRONMENT")
ASSURANCE = {
    "NONE_EXIT_CODE_ONLY": "plain test run; exit code only, no evidence object",
    "HEURISTIC_SELECTION_NO_CERTIFICATE": "pytest-testmon change-based selection; not an equivalent guarantee",
    "VEP_PROTECTED_FRESH_CERTIFICATE": "protected runner, signed evidence, exact-snapshot certificate (TRUSTED_LOCAL)",
    "BUILD_CACHE_HIT_NO_CERTIFICATE": "verified build-cache lookup of a deterministic action; no evaluation, no certificate",
    "DERIVED_ATTESTATION_NOT_CERTIFICATE": "exact-input derived attestation naming original signed evidence; not a certificate",
    "NOT_APPLICABLE": "size or latency measurement, no verification claim",
    "SIMULATED": "synthetic policy simulation, no verification",
}
ASSUR_BY_CONFIG = {
    "DIRECT": "NONE_EXIT_CODE_ONLY", "A": "NONE_EXIT_CODE_ONLY", "C_seq_direct": "NONE_EXIT_CODE_ONLY", "D_parallel_direct": "NONE_EXIT_CODE_ONLY",
    "DIRECT_SEQ": "NONE_EXIT_CODE_ONLY", "DIRECT_PAR": "NONE_EXIT_CODE_ONLY",
    "TESTMON": "HEURISTIC_SELECTION_NO_CERTIFICATE", "B": "HEURISTIC_SELECTION_NO_CERTIFICATE",
    "VEP_PLAIN": "VEP_PROTECTED_FRESH_CERTIFICATE", "E": "VEP_PROTECTED_FRESH_CERTIFICATE", "E_vep_1": "VEP_PROTECTED_FRESH_CERTIFICATE",
    "F_vep_parallel": "VEP_PROTECTED_FRESH_CERTIFICATE", "F2": "BUILD_CACHE_HIT_NO_CERTIFICATE", "F2_miss": "VEP_PROTECTED_FRESH_CERTIFICATE",
}
METRIC_UNITS = {"wall_s": "s", "cpu_s": "s", "child_cpu_s": "s", "peak_child_rss_mb": "MB", "peak_single_child_rss_mb": "MB", "throughput_jobs_per_s": "jobs/s",
                "mean_latency_s": "s", "max_latency_s": "s"}


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git_commit(rel: str) -> str:
    r = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--", rel], capture_output=True, text=True)
    return r.stdout.strip() or "untracked"


def cohort_of(host: dict | None) -> str:
    if not host:
        return "none"
    plat = str(host.get("platform", ""))
    if plat.startswith("macOS"):
        return f"macos-arm64-{host.get('cpus')}cpu-local"
    if plat.startswith("Linux"):
        return f"hosted-linux-azure-{host.get('cpus')}cpu"
    return "unknown"


def host_view(h: dict | None) -> dict:
    if not h:
        return {}
    keep = ("platform", "machine", "cpus", "cpu_model", "python", "kernel", "mem_total_mb", "power", "load_avg_1m_at_start")
    return {k: h[k] for k in keep if k in h}


T_CRIT = [(1, 12.706), (2, 4.303), (3, 3.182), (4, 2.776), (5, 2.571), (6, 2.447), (7, 2.365), (8, 2.306), (9, 2.262), (10, 2.228), (15, 2.131), (20, 2.086), (30, 2.042), (10**9, 1.96)]


def mean_ci95(samples: list[float]) -> dict | None:
    """Student-t 95% interval of the mean of the raw samples (df = n-1); None when there are fewer than 2 samples."""
    n = len(samples)
    if n < 2 or not all(isinstance(x, (int, float)) for x in samples):
        return None
    m = sum(samples) / n
    sd = (sum((x - m) ** 2 for x in samples) / (n - 1)) ** 0.5
    t = [v for df, v in T_CRIT if df >= n - 1][0]
    h = t * sd / n ** 0.5
    return {"method": "student-t 95% of the mean of the raw samples", "lo": round(m - h, 6), "hi": round(m + h, 6), "n": n}


class Builder:
    def __init__(self):
        self.sources: list[dict] = []
        self.obs: list[dict] = []
        self.comps: list[dict] = []

    def source(self, rel: str, kind: str, classification: str, *, cohort="none", project=None, project_commit=None, vep_commit=None, note="", host=None) -> dict:
        p = ROOT / rel
        s = {"path": rel, "sha256": sha(p), "bytes": p.stat().st_size, "git_commit": git_commit(rel), "kind": kind, "classification": classification,
             "cohort": cohort, "project": project, "project_commit": project_commit, "vep_commit": vep_commit, "host": host_view(host), "note": note, "observations": 0}
        assert classification in CLASSES, classification
        self.sources.append(s)
        return s

    def add(self, src: dict, **kw) -> None:
        rec = {"source_path": src["path"], "source_sha256": src["sha256"], "vep_commit": src["vep_commit"], "project": src["project"], "project_commit": src["project_commit"],
               "cohort": src["cohort"], "host": src["host"], "classification": src["classification"], "warmups": None, "samples_n": None, "correctness_gate": None,
               "cache_eligibility": "n/a", "variance": None, "confidence_interval": None, "limitations": []}
        rec.update(kw)
        if rec.get("samples") and rec["confidence_interval"] is None:
            rec["confidence_interval"] = mean_ci95(rec["samples"])
        rec["id"] = f"{len(self.obs):05d}"
        assert rec["assurance"] in ASSURANCE, rec["assurance"]
        self.obs.append(rec)
        src["observations"] += 1


def stats(d: dict) -> dict:
    return {k: d[k] for k in ("n", "mean", "median", "min", "max", "sd", "stdev") if k in d}


def paired(b: Builder, rel: str, cohort_override=None):
    d = json.loads((ROOT / rel).read_text())
    host = d["host"]
    qual = None
    if "hosted-linux" in rel:
        q = json.loads((ROOT / "benchmarks/results/hosted-linux/qualification-report.json").read_text())
        qual = q["projects"][d["project"]]["validity"]["status"]
    first = next(iter(d["scenarios"].values()))
    env_ok = None
    cls = "MEASURED" if qual == "VALID" else "INVALID_ENVIRONMENT"
    note = ("hosted ubuntu-24.04 run 39457964415, qualification VALID (load<2.0, idle>=75%, direct CV<=5%)" if qual == "VALID"
            else "controlled local run whose own reporting criteria (CPU idle >= 75%, load < 2.0) were NOT met: load average ~5, minimum idle ~60%; qualitatively consistent with the hosted run, not citable as a quiet-machine result")
    s = b.source(rel, "paired_benchmark", cls, cohort=cohort_of(host), project=d["project"], project_commit=d["pinned_commit"], vep_commit=d["vep_commit"], note=note, host={**host, "load_avg_1m_at_start": d["load_avg_1m_at_start"]})
    for scen, sc in d["scenarios"].items():
        blocks = sc["blocks"]
        warm = len(sc["warmup_blocks"])
        for cfg, cs in sc["analysis"]["configs"].items():
            assurance = ASSUR_BY_CONFIG.get(cfg)
            if cfg == "VEP_OPT":
                assurance = "BUILD_CACHE_HIT_NO_CERTIFICATE" if scen == "S2_warm_unchanged" else "VEP_PROTECTED_FRESH_CERTIFICATE"
            raw = {m: [r["runs"][cfg][k] for r in blocks if cfg in r["runs"]] for m, k in (("wall_s", "wall"), ("cpu_s", "cpu"), ("peak_child_rss_mb", "rss"))}
            for metric in ("wall_s", "cpu_s", "peak_child_rss_mb"):
                b.add(s, scenario=scen, operation=f"{scen}:{cfg}", config=cfg, assurance=assurance, metric=metric, units=METRIC_UNITS[metric],
                      stats=stats(cs[metric]), samples=raw[metric], warmups=warm, samples_n=cs[metric]["n"], variance={"sd": cs[metric]["sd"]},
                      correctness_gate=d["correctness_gate"].get({"VEP_OPT": "VEP_OPT_buildcache"}.get(cfg, cfg)),
                      cache_eligibility=("exact-snapshot build-cache hit; deterministic action only" if cfg == "VEP_OPT" and scen == "S2_warm_unchanged" else "n/a"),
                      cache={"hits": cs.get("cache_hits"), "misses": cs.get("cache_misses")} if "cache_hits" in cs else None,
                      limitations=[note] if cls != "MEASURED" else ["two projects, one platform per cohort; no extrapolation to other codebases"])
        for pair, cmpv in sc["analysis"]["comparisons"].items():
            b.comps.append({"source_path": rel, "source_sha256": s["sha256"], "cohort": s["cohort"], "classification": cls, "project": d["project"], "scenario": scen, "comparison": pair,
                            "welch_preregistered": cmpv["welch_preregistered"], "paired_bootstrap": cmpv["paired_bootstrap"], "cpu_mean_ratio": cmpv.get("cpu_mean_ratio"),
                            "assurance_note": "compared contracts differ; see the assurance of each side"})


def compare(b: Builder, rel: str):
    d = json.loads((ROOT / rel).read_text())
    host = d["host"]
    s = b.source(rel, "exploratory_comparison", "INVALID_ENVIRONMENT", cohort=cohort_of(host), project=d["project"], project_commit=d["pinned_commit"], vep_commit=d["vep_commit"],
                 note="first exploratory local comparison: 1-minute load average ~9.9 at start, pre-fix runner (VEP e632a4b); superseded by the paired runs; kept for the record", host=host)
    for scen in ("T1_cold_verify", "T2_unchanged_rerun", "T3_small_edit", "T4_batch"):
        sc = d[scen]
        for cfg, w in sc["wall"].items():
            b.add(s, scenario=scen, operation=f"{scen}:{cfg}", config=cfg, assurance=ASSUR_BY_CONFIG.get(cfg, "VEP_PROTECTED_FRESH_CERTIFICATE"), metric="wall_s", units="s", stats=stats(w),
                  samples=w.get("samples"), samples_n=w["n"], variance={"sd": w["sd"]}, warmups=None, correctness_gate=None,
                  cache_eligibility=("deterministic BuildAction result cache; no certificate" if cfg == "F2" else "n/a"),
                  limitations=["load average ~9.9 at start", "pre-fix runner", "batch scenario uses " + str(sc.get("n_candidates", "")) + " candidates" if scen == "T4_batch" else "single candidate"])
        for cfg, w in sc.get("child_cpu", {}).items():
            b.add(s, scenario=scen, operation=f"{scen}:{cfg}", config=cfg, assurance=ASSUR_BY_CONFIG.get(cfg, "VEP_PROTECTED_FRESH_CERTIFICATE"), metric="child_cpu_s", units="s", stats=stats(w),
                  samples=w.get("samples"), samples_n=w["n"], variance={"sd": w["sd"]}, limitations=["load average ~9.9 at start"])
        for pair, v in sc.get("verdicts", {}).items():
            b.comps.append({"source_path": rel, "source_sha256": s["sha256"], "cohort": s["cohort"], "classification": "INVALID_ENVIRONMENT", "project": d["project"], "scenario": scen,
                            "comparison": pair, "welch_preregistered": {k: v.get(k) for k in ("baseline_mean_s", "vep_mean_s", "diff_s", "rel_diff", "rel_ci95", "verdict", "welch_df")},
                            "paired_bootstrap": None, "cpu_mean_ratio": None, "assurance_note": "compared contracts differ"})


def scaling(b: Builder):
    rel = "benchmarks/results/controller_scaling.json"
    d = json.loads((ROOT / rel).read_text())
    s = b.source(rel, "controller_scaling", "MEASURED", cohort=cohort_of(d["host"]), vep_commit=None, host=d["host"],
                 note="idle apart from the benchmark (no formal load gate recorded); 32 tiny (~65 ms) real unittest evaluations per rep, 3 reps; throughput per setting; not a scale claim beyond 16 processes")
    for name, r in d["results"].items():
        workers = name.split("_")[1] if name.startswith("controller_") else "0"
        assurance = "VEP_PROTECTED_FRESH_CERTIFICATE"
        for metric, v in r.items():
            if not isinstance(v, dict) or "mean" not in v:
                continue
            b.add(s, scenario="controller_scaling_32_jobs", operation=name, config=name, assurance=assurance, metric=metric, units=METRIC_UNITS.get(metric, "count"),
                  stats=stats(v), samples_n=d["reps"], warmups=0, variance={"sd": v.get("stdev")}, correctness_gate={"all_candidates_certified_once": r.get("correct_all_reps")},
                  limitations=["tiny CPU-bound jobs dominated by process start-up", f"workers={workers}"])


def stage_profiles(b: Builder):
    for n in (200, 1000):
        rel = f"benchmarks/results/stage-profile-{n}.json"
        d = json.loads((ROOT / rel).read_text())
        s = b.source(rel, "stage_profile", "MEASURED", cohort=cohort_of(d["host"]), vep_commit=None, host=d["host"],
                     note=f"synthetic project ({d['project']['files']} files, {d['project']['tests']} trivial tests), inclusive stage times, one macOS host, no formal idle gate")
        sm = d["summary"]
        b.add(s, scenario=f"stage_profile_{n}", operation="full_workflow", config="vep_full", assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric="wall_ms", units="ms",
              stats=stats(sm["full_workflow_ms"]), samples=[r["full_workflow_ms"] for r in d["raw"] if not r["warmup"]], samples_n=d["runs"], warmups=d["warmup_runs"], limitations=["inclusive; synthetic project"])
        b.add(s, scenario=f"stage_profile_{n}", operation="derive_export_verify", config="vep_reuse", assurance="DERIVED_ATTESTATION_NOT_CERTIFICATE", metric="wall_ms", units="ms",
              stats=stats(sm["reuse_derive_export_verify_ms"]), samples=[r["reuse_derive_export_verify_ms"] for r in d["raw"] if not r["warmup"]], samples_n=d["runs"], warmups=d["warmup_runs"],
              cache_eligibility="identical snapshot, policy, runner, evaluator, environment; trusted-local evidence only", limitations=["not a certificate", "synthetic project"])
        for stage, ms in sm["stages_median_ms"].items():
            b.add(s, scenario=f"stage_profile_{n}", operation=f"stage:{stage}", config="vep_full", assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric="median_ms", units="ms",
                  stats={"median": ms}, samples_n=d["runs"], warmups=d["warmup_runs"], limitations=["inclusive time: nested stages overlap"])


def misc(b: Builder):
    rel = "benchmarks/results/paired-object-parse-cache.json"
    d = json.loads((ROOT / rel).read_text())
    s = b.source(rel, "negative_experiment", "MEASURED", cohort="macos-arm64-12cpu-local", note="interleaved before/after, 500 modules + 500 tests; decision REJECTED_NOT_ADOPTED under the 10%/50 ms rule", host={})
    for k in ("before_full_workflow_median_ms", "after_full_workflow_median_ms", "before_policy_validation_median_ms", "after_policy_validation_median_ms"):
        b.add(s, scenario="object_parse_cache", operation=k, config=k.split("_")[0], assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric=k, units="ms",
              stats={"median": sorted(d[k])[len(d[k]) // 2], "min": min(d[k]), "max": max(d[k])}, samples=d[k], samples_n=len(d[k]), warmups=1, limitations=[d["decision"]])
    rel = "benchmarks/results/mcp-context-profile.json"
    d = json.loads((ROOT / rel).read_text())
    s = b.source(rel, "mcp_context_profile", "MEASURED", cohort="macos-arm64-12cpu-local", note="tool-definition bytes, response bytes and stdio latency; token figures are bytes/4 estimates, not provider usage", host={})
    b.add(s, scenario="mcp", operation="tools_list_bytes", config="vep-mcp", assurance="NOT_APPLICABLE", metric="bytes", units="bytes", stats={"mean": d["tools_list_bytes"]}, samples_n=1)
    for k, v in d["response_bytes"].items():
        b.add(s, scenario="mcp", operation=f"response:{k}", config="vep-mcp", assurance="NOT_APPLICABLE", metric="bytes", units="bytes", stats={"mean": v}, samples_n=1)
    lat = d["vep_status_latency_ms"]
    b.add(s, scenario="mcp", operation="vep_status_latency", config="vep-mcp", assurance="NOT_APPLICABLE", metric="latency_ms", units="ms", stats={"median": lat["median"], "p95": lat["p95"]}, samples_n=lat["n"])
    rel = "benchmarks/results.json"
    d = json.loads((ROOT / rel).read_text())
    s = b.source(rel, "synthetic_simulation", "SYNTHETIC", note="every probability, price and token count is an assumption; measures no real model, vendor or verifier", host={})
    for pol, r in d["results"].items():
        b.add(s, scenario="policy_simulation", operation=pol, config=pol, assurance="SIMULATED", metric="total_cost_usd", units="USD (assumed prices)", stats={"mean": float(r["total_cost_usd"])}, samples_n=d["params"]["n_tasks"],
              limitations=["SIMULATED - synthetic assumptions, not measurement"])


def reports(b: Builder):
    for rel, note in (("docs/BENCHMARKS.md", "report of the synthetic simulation"), ("docs/BENCHMARK_METHODOLOGY.md", "preregistered thresholds and procedures (10% relative and 50 ms absolute for wall time)"),
                      ("docs/BENCHMARK_RESULTS_PAIRED.md", "rendered report of the macOS paired run"), ("docs/BENCHMARK_RESULTS_HOSTED_LINUX.md", "rendered report of the hosted Linux paired run"),
                      ("docs/CONTROLLER_SCALING.md", "rendered report of the controller scaling run"), ("docs/PERFORMANCE_REPORT.md", "stage profile, rejected optimizations and MCP context profile"),
                      ("benchmarks/results/hosted-linux/BENCHMARK_RESULTS_HOSTED_LINUX.md", "copy of the hosted report inside the run artifact")):
        b.source(rel, "derived_report", "MEASURED" if "SIMULATION" not in note and "simulation" not in note else "SYNTHETIC", note="DERIVED from primary records listed in this dataset (no independent numbers extracted); " + note)
    for rel in sorted(str(p.relative_to(ROOT)) for p in (ROOT / "benchmarks/results/hosted-linux").glob("*") if p.is_file() and p.suffix in (".json", ".txt") and p.name not in ("paired-pyflakes.json", "paired-more-itertools.json")):
        cls = "MEASURED"
        b.source(rel, "hosted_run_artifact", cls, cohort="hosted-linux-azure-4cpu", note="supporting artifact of hosted run 39457964415 (environment probe, idle check, pins, logs or qualification report)")
    for rel in ("benchmarks/analysis/PLANNED_EXPERIMENTS.json",):
        if (ROOT / rel).exists():
            b.source(rel, "experiment_plan", "PROPOSED", note="predeclared experiments and endpoints; contains no measurements")


def build() -> Builder:
    b = Builder()
    paired(b, "benchmarks/results/paired-pyflakes.json")
    paired(b, "benchmarks/results/paired-more-itertools.json")
    paired(b, "benchmarks/results/hosted-linux/paired-pyflakes.json")
    paired(b, "benchmarks/results/hosted-linux/paired-more-itertools.json")
    compare(b, "benchmarks/results/compare-pyflakes.json")
    compare(b, "benchmarks/results/compare-more-itertools.json")
    scaling(b)
    stage_profiles(b)
    misc(b)
    reports(b)
    return b


def aggregates(obs: list[dict]) -> dict:
    """Per cohort/project/scenario/config medians of wall_s ONLY for MEASURED observations; cohorts are never combined."""
    out: dict = {}
    for o in obs:
        if o["classification"] != "MEASURED" or o["metric"] != "wall_s" or not o.get("stats", {}).get("median"):
            continue
        key = f"{o['cohort']}|{o['project']}|{o['scenario']}"
        out.setdefault(key, {})[o["config"]] = {"median_wall_s": o["stats"]["median"], "assurance": o["assurance"], "n": o["samples_n"]}
    return dict(sorted(out.items()))


def render(b: Builder) -> tuple[str, str]:
    methodology = {"source": "docs/BENCHMARK_METHODOLOGY.md", "adoption_rule_wall_time": {"relative": 0.10, "absolute_s": 0.05}, "interval": "Welch 95% (preregistered) and paired bootstrap 95%",
                   "hosted_validity": {"max_load_avg_1m_at_start": 2.0, "min_valid_blocks_per_scenario": 10, "cpu_idle_pct_min": 75, "direct_cv_max": 0.05}}
    ds = {"dataset_version": 1, "classifications": list(CLASSES), "assurance_levels": ASSURANCE, "methodology": methodology,
          "sources": sorted(b.sources, key=lambda s: s["path"]), "observations": b.obs, "comparisons": b.comps, "aggregates_by_cohort": aggregates(b.obs),
          "global_limitations": ["observations from different cohorts (macOS arm64 12-cpu local vs hosted Azure 4-cpu Linux) are never averaged together",
                                 "a build-cache hit, a derived attestation, heuristic test selection and a fresh certificate are different assurance contracts; wall times are not like-for-like across them",
                                 "only two real projects (pyflakes 4.0.3, more-itertools v11.2.1) and synthetic stage-profile projects were measured"]}
    text = json.dumps(ds, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["path", "sha256", "bytes", "git_commit", "kind", "classification", "cohort", "project", "project_commit", "vep_commit", "observations", "note"])
    for s in ds["sources"]:
        w.writerow([s["path"], s["sha256"], s["bytes"], s["git_commit"], s["kind"], s["classification"], s["cohort"], s["project"] or "", s["project_commit"] or "", s["vep_commit"] or "", s["observations"], s["note"]])
    return text, buf.getvalue()


def main() -> int:
    text, csv_text = render(build())
    a, c = OUT_DIR / "master-dataset.json", OUT_DIR / "benchmark-inventory.csv"
    if "--check" in sys.argv:
        return 0 if a.exists() and c.exists() and a.read_text() == text and c.read_text() == csv_text else 1
    a.write_text(text); c.write_text(csv_text)
    print(f"wrote {a.name} ({len(text)} bytes) and {c.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
