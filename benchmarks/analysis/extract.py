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


def is_shallow() -> bool:
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True).stdout.strip() == "true"


def git_last_commit(rel: str) -> str | None:
    r = subprocess.run(["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--", rel], capture_output=True, text=True)
    return r.stdout.strip() or None


def blob_sha_at(commit: str, rel: str) -> str | None:
    r = subprocess.run(["git", "-C", str(ROOT), "show", f"{commit}:{rel}"], capture_output=True)
    return hashlib.sha256(r.stdout).hexdigest() if r.returncode == 0 else None


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
        s = {"path": rel, "sha256": sha(p), "bytes": p.stat().st_size, "kind": kind, "classification": classification,
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


def env_valid(blocks) -> tuple[bool, str]:
    """Declared reporting criteria: 1-minute load average < 2.0 and CPU idle >= 75% in every analysed block."""
    loads = [b["env"].get("load_avg_1m") for b in blocks if b.get("env")]
    idles = [b["env"].get("cpu_idle_pct") for b in blocks if b.get("env")]
    if not loads:
        return False, "no per-block environment samples recorded"
    ok = max(loads) < 2.0 and min(i for i in idles if i is not None) >= 75.0
    return ok, f"load avg {min(loads):.1f}-{max(loads):.1f}, minimum CPU idle {min(i for i in idles if i is not None):.1f}%"


def ab(b: Builder, rel: str):
    d = json.loads((ROOT / rel).read_text())
    ok, why = env_valid(d["blocks"])
    cls = "MEASURED" if ok else "INVALID_ENVIRONMENT"
    host = d["host"]
    s = b.source(rel, "ab_experiment", cls, cohort=cohort_of(host), project=f"synthetic-{d['n_files']}-files", vep_commit=d.get("vep_commit"), host=host,
                 note=f"balanced randomized paired blocks; {why}" + ("" if ok else " (declared criteria NOT met: not citable as a quiet-machine result)"))
    for arm, sm in d["summary"].items():
        for metric, st in sm.items():
            raw = [bl["runs"][arm][metric] for bl in d["blocks"] if bl in d["blocks"] and arm in bl["runs"] and metric in bl["runs"][arm] and "error" not in bl["runs"][arm]]
            b.add(s, scenario=f"ab_n{d['n_files']}_{d['change']}", operation=f"ab:{arm}", config=arm, assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric=metric, units="MB" if "rss" in metric else "s",
                  stats=stats(st), samples=raw[:len(raw)], warmups=d["warmup_blocks"], samples_n=st["n"], variance={"sd": st["sd"]}, correctness_gate={"valid_blocks": d["valid_blocks"], "excluded": len(d["excluded"])},
                  limitations=["synthetic project; same process image per arm; flags via VEP_PERF"] + ([] if ok else [why]))
    for pair, c in d["comparisons"].items():
        for m in ("wall_s", "cpu_s"):
            if m in c:
                b.comps.append({"source_path": rel, "source_sha256": s["sha256"], "cohort": s["cohort"], "classification": cls, "project": s["project"], "scenario": f"ab_n{d['n_files']}",
                                "comparison": f"{pair}:{m}", "welch_preregistered": c[m]["welch_preregistered"], "paired_bootstrap": c[m]["paired_bootstrap"], "cpu_mean_ratio": None,
                                "assurance_note": "same assurance on both sides (fresh protected certificate)"})


def scale(b: Builder, rel: str):
    d = json.loads((ROOT / rel).read_text())
    s = b.source(rel, "scale_profile", "MEASURED" if d.get("load_avg_1m_at_start", 99) < 2.0 else "INVALID_ENVIRONMENT", cohort=cohort_of(d["host"]), project="synthetic-scale", host={**d["host"], "load_avg_1m_at_start": d.get("load_avg_1m_at_start")},
                 note=f"stage profile with instrumentation overhead; load avg at start {d.get('load_avg_1m_at_start')}")
    for n, sz in d["sizes"].items():
        sm = sz["summary"]
        b.add(s, scenario=f"scale_{n}", operation="full_workflow", config="vep_full", assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric="wall_s", units="s", stats=sm["wall_s"],
              samples=[r["wall_s"] for r in sz["raw"] if not r["warmup"]], samples_n=d["runs_per_size"], warmups=d["warmup_runs"], limitations=["instrumented run: use for ranking stages, not absolute speed"])
        for st, v in sm["stages_median"].items():
            b.add(s, scenario=f"scale_{n}", operation=f"stage:{st}", config="vep_full", assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric="excl_s", units="s", stats={"median": v["excl_s"]},
                  samples_n=d["runs_per_size"], warmups=d["warmup_runs"], limitations=[f"inclusive {v['incl_s']} s; calls {v['calls']}"])


def agent(b: Builder, rel: str):
    d = json.loads((ROOT / rel).read_text())
    envs = [r["env"] for sc in d["scenarios"].values() for r in sc["raw"] if not r["warmup"]]
    ok, why = env_valid([{"env": e} for e in envs])
    cls = "MEASURED" if ok else "INVALID_ENVIRONMENT"
    s = b.source(rel, "agent_workflow", cls, cohort=cohort_of(d["host"]), project=d["project"], project_commit=d["project_commit"], host=d["host"],
                 note=f"deterministic agent traces; each repetition is ONE independent sample per system and step (steps of one repetition are not independent); {why}")
    for sc, body in d["scenarios"].items():
        reps = [r for r in body["raw"] if not r["warmup"]]
        systems = sorted({k for r in reps for k in r["systems"]})
        for system in systems:
            labels = []
            for r in reps:
                for st in r["systems"].get(system, {}).get("steps", []):
                    if st["label"] not in labels:
                        labels.append(st["label"])
            for label in labels:
                for metric in ("wall_s", "feedback_s", "verdict_s", "authorized_s", "cpu_s", "rss_mb"):
                    xs = [st[metric] for r in reps for st in r["systems"].get(system, {}).get("steps", []) if st["label"] == label and st.get(metric) is not None]
                    if not xs:
                        continue
                    oks = [st.get("outcome_ok") for r in reps for st in r["systems"].get(system, {}).get("steps", []) if st["label"] == label and "outcome_ok" in st]
                    outs = sorted({st.get("outcome") for r in reps for st in r["systems"].get(system, {}).get("steps", []) if st["label"] == label and st.get("outcome")})
                    b.add(s, scenario=sc, operation=f"{sc}:{label}", config=system, assurance=("VEP_PROTECTED_FRESH_CERTIFICATE" if system in ("VEP_BASE", "VEP_OPT") else
                          "BUILD_CACHE_HIT_NO_CERTIFICATE" if False else ASSUR_BY_CONFIG.get(system, "NONE_EXIT_CODE_ONLY") if system in ("DIRECT_SEQ", "DIRECT_PAR", "TESTMON") else "VEP_PROTECTED_FRESH_CERTIFICATE"),
                          metric=metric, units="MB" if metric == "rss_mb" else "s", stats={"mean": sum(xs) / len(xs), "median": sorted(xs)[len(xs) // 2], "min": min(xs), "max": max(xs), "n": len(xs)},
                          samples=xs, samples_n=len(xs), warmups=d["warmups"], correctness_gate={"outcome_ok_all": all(o for o in oks if o is not None) if oks else None, "outcomes": outs},
                          cache_eligibility="derived attestation used only where the step was eligible; outcome field says which" if system == "VEP_REUSE" else "n/a",
                          limitations=["steps of one repetition are correlated; only repetitions are independent"] + ([] if ok else [why]))


def workers(b: Builder, rel: str):
    d = json.loads((ROOT / rel).read_text())
    ok, why = env_valid([{"env": r["env"]} for r in d["raw"] if not r["warmup"]])
    s = b.source(rel, "worker_scaling", "MEASURED" if ok else "INVALID_ENVIRONMENT", cohort=cohort_of(d["host"]), project=d["project"], project_commit=d["project_commit"], host=d["host"],
                 note=f"{d['candidates_per_rep']} candidates per repetition; {why}")
    for w, sm in d["summary"].items():
        for key, metric, unit in (("vep_jobs_per_s", "throughput_jobs_per_s", "jobs/s"), ("vep_p95_latency_s", "p95_latency_s", "s"), ("vep_cpu_total_s", "child_cpu_s", "s"), ("vep_rss_children_max_mb", "peak_child_rss_mb", "MB")):
            if sm.get(key):
                b.add(s, scenario=f"worker_scaling_{d['candidates_per_rep']}", operation=f"workers={w}", config=f"vep_{w}_workers", assurance="VEP_PROTECTED_FRESH_CERTIFICATE", metric=metric, units=unit, stats=stats(sm[key]),
                      samples_n=sm[key]["n"], warmups=d["warmups"], correctness_gate={"all_certified_once": sm.get("vep_all_certified_once")}, limitations=[] if ok else [why])
        b.add(s, scenario=f"worker_scaling_{d['candidates_per_rep']}", operation=f"workers={w}", config=f"direct_{w}_parallel", assurance="NONE_EXIT_CODE_ONLY", metric="throughput_jobs_per_s", units="jobs/s",
              stats=stats(sm["direct_jobs_per_s"]), samples_n=sm["direct_jobs_per_s"]["n"], warmups=d["warmups"], limitations=[] if ok else [why])


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
    for pat, fn in (("benchmarks/results/ab-*.json", ab), ("benchmarks/results/scale-profile-*.json", scale), ("benchmarks/results/agent-workflow-*.json", agent), ("benchmarks/results/worker-scaling-*.json", workers),
                    ("benchmarks/results/hosted-linux-perf/ab-*.json", ab), ("benchmarks/results/hosted-linux-perf/scale-profile-*.json", scale),
                    ("benchmarks/results/hosted-linux-perf/agent-workflow-*.json", agent), ("benchmarks/results/hosted-linux-perf/worker-scaling-*.json", workers)):
        for p in sorted(ROOT.glob(pat)):
            fn(b, str(p.relative_to(ROOT)))
    for p in sorted((ROOT / "benchmarks/results/hosted-linux-perf").glob("*")) if (ROOT / "benchmarks/results/hosted-linux-perf").exists() else []:
        rel = str(p.relative_to(ROOT))
        if p.is_file() and not any(x["path"] == rel for x in b.sources):
            b.source(rel, "hosted_run_artifact", "MEASURED", cohort="hosted-linux-azure-4cpu", note="supporting artifact of the hosted performance run (environment, idle checks, pins, logs)")
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
    w.writerow(["path", "sha256", "bytes", "kind", "classification", "cohort", "project", "project_commit", "vep_commit", "observations", "note"])
    for s in ds["sources"]:
        w.writerow([s["path"], s["sha256"], s["bytes"], s["kind"], s["classification"], s["cohort"], s["project"] or "", s["project_commit"] or "", s["vep_commit"] or "", s["observations"], s["note"]])
    return text, buf.getvalue()


HISTORY = OUT_DIR / "source-history.json"


def history_entries(sources: list[dict]) -> list[dict]:
    """Commit lineage of each source file. This is provenance about the repository HISTORY, which a shallow checkout does not contain, so it is kept apart from the
    content dataset (whose bytes must reproduce anywhere) and is verified wherever history exists: the recorded commit must contain a blob with the recorded SHA-256."""
    prev = {}
    if HISTORY.exists():
        for e in json.loads(HISTORY.read_text())["entries"]:
            prev[(e["path"], e["sha256"])] = e["last_commit"]
    out = []
    for s in sorted(sources, key=lambda x: x["path"]):
        commit = prev.get((s["path"], s["sha256"]))
        if commit is None and not is_shallow():
            commit = git_last_commit(s["path"])
            if commit and blob_sha_at(commit, s["path"]) != s["sha256"]:
                commit = None  # modified or untracked since: no commit contains exactly this content yet
        out.append({"path": s["path"], "sha256": s["sha256"], "last_commit": commit})
    return out


def check_history(sources: list[dict]) -> list[str]:
    """Coverage always; blob-at-commit verification when the history is available. A null commit means the content is not in any commit yet (pending)."""
    problems = []
    doc = json.loads(HISTORY.read_text()) if HISTORY.exists() else {"entries": []}
    by = {(e["path"], e["sha256"]): e for e in doc["entries"]}
    for s in sources:
        e = by.get((s["path"], s["sha256"]))
        if e is None:
            problems.append(f"{s['path']}: no history entry for sha256 {s['sha256'][:12]} (regenerate in a full clone)")
        elif e["last_commit"] and not is_shallow() and blob_sha_at(e["last_commit"], s["path"]) != s["sha256"]:
            problems.append(f"{s['path']}: commit {e['last_commit'][:12]} does not contain content {s['sha256'][:12]}")
    return problems


def main() -> int:
    b = build()
    text, csv_text = render(b)
    a, c = OUT_DIR / "master-dataset.json", OUT_DIR / "benchmark-inventory.csv"
    if "--check" in sys.argv:
        ok = a.exists() and c.exists() and a.read_text() == text and c.read_text() == csv_text
        probs = check_history(b.sources)
        for p in probs:
            print("history:", p)
        return 0 if ok and not probs else 1
    a.write_text(text); c.write_text(csv_text)
    HISTORY.write_text(json.dumps({"note": "commit lineage of each inventoried file; verified by extract.py --check wherever repository history exists", "entries": history_entries(b.sources)}, indent=1, sort_keys=True) + "\n")
    print(f"wrote {a.name}, {c.name} and {HISTORY.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
