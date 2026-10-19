"""Run the synthetic benchmark twice with the same seed, verify reproducibility, write the report.

    python benchmarks/run_simulation.py [--seed N] [--tasks N] [--out-json PATH] [--out-md PATH]

ALL OUTPUT IS SIMULATED. Nothing here measures a real model.
"""
from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from vep.simulation import STRATEGIES, SimParams, run_report  # noqa: E402


def table(results: dict) -> list[str]:
    lines = ["| Strategy | Correctly accepted | Incorrect acceptances | Unaccepted tasks | Total tokens | Total cost (USD) | Cost per correct acceptance (USD) |",
             "|---|---|---|---|---|---|---|"]
    for s in STRATEGIES:
        m = results[s]
        lines.append(f"| {s} | {m['correctly_accepted_fraction']} | {m['incorrect_acceptances']} ({m['incorrect_acceptance_fraction']}) | "
                     f"{m['unaccepted_tasks']} | {m['total_tokens']} | {m['total_cost_usd']} | {m['cost_per_correct_acceptance_usd']} |")
    return lines


def cheapest(results: dict) -> str:
    ok = {s: Decimal(m["cost_per_correct_acceptance_usd"]) for s, m in results.items() if m["cost_per_correct_acceptance_usd"]}
    return min(ok, key=lambda s: (ok[s], s))


def render(rep: dict, seed: int) -> str:
    L = ["# Synthetic Benchmark Report", "",
         "**Status: SIMULATED.** Every probability, price and token count below is an explicit assumption in `SimParams`. "
         "Nothing here measures any real model, vendor, price list or verifier. No policy is claimed globally optimal; "
         "statements hold only under these assumptions, constraints and baselines.", "",
         f"Reproduce: `python benchmarks/run_simulation.py --seed {seed} --tasks {rep['params']['n_tasks']}` "
         f"(result sha256 `{rep['result_sha256']}`; the script runs the simulation twice and fails if the results differ).", "",
         "## Policies", "",
         "* A_strong_once: strong model once, accepted only if the verifier accepts.",
         "* B_strong_retry: strong model with up to `retries` extra attempts after verifier rejection.",
         "* C_cheap_first_cascade: cheap model; if rejected, strong model once.",
         "* D_adaptive_routing: noisy difficulty estimate; easy-looking tasks use the cascade, others go straight to strong.",
         "* E_double_verified_cascade: as C but each model's output must pass two sequential verifiers with dependence `rho`.", "",
         "## Assumptions", ""]
    L += [f"* {a}" for a in rep["assumptions"]]
    L += ["", "## Parameters", "", "```json", json.dumps(rep["params"], indent=1, sort_keys=True), "```", "",
          "## Results (default assumptions)", ""] + table(rep["results"])
    best = cheapest(rep["results"])
    L += ["", f"Under these default assumptions the lowest cost per correct acceptance is **{best}**; "
          "its incorrect-acceptance count (column above) is the price paid for that cost, and it is not a statement about real systems.", ""]
    L += ["## Sensitivity", "", f"Each row re-runs all five policies with {rep['sensitivity_n_tasks']} tasks. "
          "Cell = cost per correct acceptance (USD) / incorrect acceptances.", "",
          "| Axis | " + " | ".join(STRATEGIES) + " | Lowest cost/correct |", "|---|" + "---|" * (len(STRATEGIES) + 1)]
    for row in rep["sensitivity"]:
        cells = [f"{row['results'][s]['cost_per_correct_acceptance_usd']} / {row['results'][s]['incorrect_acceptances']}" for s in STRATEGIES]
        L.append(f"| {json.dumps(row['axis'], sort_keys=True)} | " + " | ".join(cells) + f" | {cheapest(row['results'])} |")
    winners = {cheapest(r["results"]) for r in rep["sensitivity"]}
    L += ["", f"Distinct lowest-cost policies across the sensitivity grid: {sorted(winners)}. "
          "A change of winner along an axis shows that the ranking is assumption-dependent.", "",
          "## Reading guide", "",
          "* Lower cost per correct acceptance is not safer: compare the incorrect-acceptance counts.",
          "* Raising `verifier_rho` weakens the benefit of double verification (see axis rows with `verifier_rho`).",
          "* Compare to the closed-form checks in `docs/EVIDENCE.md` (geometric retry cost, false-acceptance product).",
          "",
          "## Result classification", "",
          "| Class | Where |", "|---|---|",
          "| SYNTHETIC model results | every table above (illustrative assumptions, seeded, reproducible) |",
          "| MEASURED local performance | the timing line below (machine-dependent) |",
          "| LITERATURE-REPORTED results | none are reproduced here; see `docs/EVIDENCE.md` for citations used only as motivation |", ""]
    return "\n".join(L)


def economics_sections() -> list[str]:
    """Deterministic sweeps over the closed-form economics (SYNTHETIC inputs; no measurement of any provider)."""
    from vep import cache_planner as cp, routing as rt
    L = ["## Prompt-cache sensitivity (SYNTHETIC, closed-form)", "",
         "Prefix 10,000 tokens, suffix 500, output 1,000; input $3/Mtok, output $15/Mtok; write 1.25x, read 0.10x (placeholder multipliers).", "",
         "| hit probability | reuses | recommendation | break-even total requests | expected savings (USD) |", "|---|---|---|---|---|"]
    for h in ("1", "0.9", "0.5", "0.2"):
        for n in (1, 3, 10):
            p = cp.plan(cp.CacheInputs.build(prefix_tokens=10000, suffix_tokens=500, output_tokens=1000, ordinary_input_price="3",
                output_price="15", cache_write_multiplier="1.25", cache_read_multiplier="0.1", expected_reuses=n, estimated_hit_probability=h))
            L.append(f"| {h} | {n} | {p['recommendation']} | {p['break_even_total_requests']} | {p['expected_savings_usd']} |")
    L += ["", "## Routing sensitivity (SYNTHETIC)", "",
          "Cheap model: $0.25/$1.25 per Mtok; strong: $3/$15. Task: 8,000 input / 1,500 output tokens, requires success lower bound 0.9.", "",
          "| cheap false-accept bound | cheap acceptance A | verification cost (USD) | budget (USD) | decision | selected |", "|---|---|---|---|---|---|"]
    def model(name, pin, pout, acc, lb, fa=None, vc="0"):
        d = dict(name=name, price_in_per_m=pin, price_out_per_m=pout, context_capacity=200000, capabilities=["code"],
                 acceptance_estimate=acc, success_lower_bound=lb, latency_s="3", max_risk="high", evidence_source="supplied",
                 verification_cost=vc)
        if fa is not None:
            d["false_accept_upper"] = fa
        return rt.ModelOption.from_dict(d)
    for fa in ("0.001", "0.05", None):
        for acc in ("0.8", "0.3"):
            for vc, budget in (("0", None), ("0.05", None), ("0", "0.05")):
                task = rt.Task.from_dict({"input_tokens": 8000, "output_tokens": 1500, "required_capabilities": ["code"],
                    "min_success_lower_bound": "0.9", "allowed_sources": ["supplied"], "max_false_accept": "0.01",
                    **({"budget_available": budget} if budget else {})})
                r = rt.select([model("cheap", "0.25", "1.25", acc, "0.5", fa, vc), model("strong", "3", "15", "0.9", "0.95", None, vc)], task)
                sel = r["selected"]
                L.append(f"| {fa} | {acc} | {vc} | {budget or 'none'} | {r['decision']} | {(sel['kind'] + ': ' + '->'.join(sel['models'])) if sel else '-'} |")
    L += ["", "Reading: a cascade is chosen only when the cheap model's false-accept bound is *measured and small enough*, "
          "its expected cost is lower after verification costs, and the worst-case cost fits the budget. "
          "Changing any of these flips the decision, which is the point of the sensitivity sweep.", ""]
    return L


def measured_local_performance(n_tasks: int) -> list[str]:
    import platform
    import time
    t0 = time.perf_counter(); run_report(SimParams(n_tasks=n_tasks, seed=1), with_sensitivity=False); t = time.perf_counter() - t0
    return ["## Measured local performance (MEASURED, machine-dependent, not part of the reproducibility hash)", "",
            f"Simulation of {n_tasks} tasks x 5 policies took {t:.2f} s wall-clock on {platform.platform()}, Python {platform.python_version()} "
            "(single run; use for regression spotting only, not as a benchmark of any model or provider).", ""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261019)
    ap.add_argument("--tasks", type=int, default=20000)
    ap.add_argument("--out-json", default=str(ROOT / "benchmarks" / "results.json"))
    ap.add_argument("--out-md", default=str(ROOT / "docs" / "BENCHMARKS.md"))
    a = ap.parse_args()
    p = SimParams(n_tasks=a.tasks, seed=a.seed)
    first, second = run_report(p), run_report(p)
    if first != second:
        print("NOT REPRODUCIBLE: two runs with the same seed differ", file=sys.stderr)
        return 1
    Path(a.out_json).write_text(json.dumps(first, indent=1, sort_keys=True) + "\n")
    Path(a.out_md).write_text(render(first, a.seed) + "\n" + "\n".join(economics_sections() + measured_local_performance(a.tasks)))
    print(f"reproducible: yes (sha256 {first['result_sha256']})")
    print(f"wrote {a.out_json} and {a.out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
