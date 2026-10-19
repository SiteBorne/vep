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
          "* Compare to the closed-form checks in `docs/EVIDENCE.md` (geometric retry cost, false-acceptance product).", ""]
    return "\n".join(L)


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
    Path(a.out_md).write_text(render(first, a.seed))
    print(f"reproducible: yes (sha256 {first['result_sha256']})")
    print(f"wrote {a.out_json} and {a.out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
