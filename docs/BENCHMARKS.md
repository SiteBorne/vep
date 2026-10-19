# Synthetic Benchmark Report

**Status: SIMULATED.** Every probability, price and token count below is an explicit assumption in `SimParams`. Nothing here measures any real model, vendor, price list or verifier. No policy is claimed globally optimal; statements hold only under these assumptions, constraints and baselines.

Reproduce: `python benchmarks/run_simulation.py --seed 20261019 --tasks 20000` (result sha256 `e98e2a562d7a5df09f90cc03a532376b80ed8c36790add89f644167e902c3b2f`; the script runs the simulation twice and fails if the results differ).

## Policies

* A_strong_once: strong model once, accepted only if the verifier accepts.
* B_strong_retry: strong model with up to `retries` extra attempts after verifier rejection.
* C_cheap_first_cascade: cheap model; if rejected, strong model once.
* D_adaptive_routing: noisy difficulty estimate; easy-looking tasks use the cascade, others go straight to strong.
* E_double_verified_cascade: as C but each model's output must pass two sequential verifiers with dependence `rho`.

## Assumptions

* task difficulty d in [0,1]; P(correct) is linear in d with the stated base/slope
* verifier accepts correct output with prob sensitivity and incorrect with prob fp
* second verifier's false accept prob = fp + rho*(1-fp) given the first accepted an incorrect output
* adaptive routing observes difficulty with Gaussian noise; thresholded
* prices are illustrative placeholders, not any vendor's pricing
* no policy here is claimed globally optimal; comparisons hold only under these assumptions

## Parameters

```json
{
 "cheap_base": 0.8,
 "cheap_in_price": "0.25",
 "cheap_out_price": "1.25",
 "cheap_slope": 0.7,
 "difficulty": "uniform",
 "in_tokens": 4000,
 "n_tasks": 20000,
 "out_tokens": 1000,
 "retries": 2,
 "router_noise": 0.15,
 "router_threshold": 0.5,
 "seed": 20261019,
 "strong_base": 0.97,
 "strong_in_price": "3.00",
 "strong_out_price": "15.00",
 "strong_slope": 0.25,
 "verifier_fp": 0.1,
 "verifier_rho": 0.5,
 "verifier_sensitivity": 0.98,
 "verify_tokens": 500
}
```

## Results (default assumptions)

| Strategy | Correctly accepted | Incorrect acceptances | Unaccepted tasks | Total tokens | Total cost (USD) | Cost per correct acceptance (USD) |
|---|---|---|---|---|---|---|
| A_strong_once | 0.826000 | 322 (0.016100) | 3158 | 110000000 | 542.500000 | 0.032839 |
| B_strong_retry | 0.975650 | 356 (0.017800) | 131 | 130691000 | 644.544250 | 0.033032 |
| C_cheap_first_cascade | 0.849950 | 1283 (0.064150) | 1718 | 165181500 | 319.645125 | 0.018804 |
| D_adaptive_routing | 0.840400 | 661 (0.033050) | 2531 | 130438000 | 396.068750 | 0.023564 |
| E_double_verified_cascade | 0.861200 | 717 (0.035850) | 2059 | 178441500 | 340.959375 | 0.019796 |

Under these default assumptions the lowest cost per correct acceptance is **C_cheap_first_cascade**; its incorrect-acceptance count (column above) is the price paid for that cost, and it is not a statement about real systems.

## Sensitivity

Each row re-runs all five policies with 5000 tasks. Cell = cost per correct acceptance (USD) / incorrect acceptances.

| Axis | A_strong_once | B_strong_retry | C_cheap_first_cascade | D_adaptive_routing | E_double_verified_cascade | Lowest cost/correct |
|---|---|---|---|---|---|---|
| {"verifier_fp": 0.02, "verifier_rho": 0.0} | 0.032991 / 17 | 0.032782 / 12 | 0.019650 / 67 | 0.023705 / 44 | 0.019809 / 1 | C_cheap_first_cascade |
| {"verifier_fp": 0.02, "verifier_rho": 0.5} | 0.032991 / 17 | 0.032782 / 12 | 0.019650 / 67 | 0.023705 / 44 | 0.019728 / 39 | C_cheap_first_cascade |
| {"verifier_fp": 0.02, "verifier_rho": 1.0} | 0.032991 / 17 | 0.032782 / 12 | 0.019650 / 67 | 0.023705 / 44 | 0.019665 / 71 | C_cheap_first_cascade |
| {"verifier_fp": 0.1, "verifier_rho": 0.0} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019847 / 40 | C_cheap_first_cascade |
| {"verifier_fp": 0.1, "verifier_rho": 0.5} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019490 / 194 | C_cheap_first_cascade |
| {"verifier_fp": 0.1, "verifier_rho": 1.0} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019203 / 321 | C_cheap_first_cascade |
| {"verifier_fp": 0.3, "verifier_rho": 0.0} | 0.032991 / 248 | 0.032732 / 251 | 0.017339 / 965 | 0.023071 / 486 | 0.019117 / 314 | C_cheap_first_cascade |
| {"verifier_fp": 0.3, "verifier_rho": 0.5} | 0.032991 / 248 | 0.032732 / 251 | 0.017339 / 965 | 0.023071 / 486 | 0.018235 / 640 | C_cheap_first_cascade |
| {"verifier_fp": 0.3, "verifier_rho": 1.0} | 0.032991 / 248 | 0.032732 / 251 | 0.017339 / 965 | 0.023071 / 486 | 0.017334 / 952 | E_double_verified_cascade |
| {"strong_to_cheap_price_ratio": "2"} | 0.005625 / 85 | 0.005590 / 87 | 0.005576 / 333 | 0.005179 / 171 | 0.005733 / 194 | D_adaptive_routing |
| {"strong_to_cheap_price_ratio": "12"} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019490 / 194 | C_cheap_first_cascade |
| {"strong_to_cheap_price_ratio": "60"} | 0.164346 / 85 | 0.163311 / 87 | 0.083493 / 333 | 0.111418 / 171 | 0.085523 / 194 | C_cheap_first_cascade |
| {"difficulty": "uniform"} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019490 / 194 | C_cheap_first_cascade |
| {"difficulty": "hard_skew"} | 0.034545 / 102 | 0.034424 / 131 | 0.023439 / 393 | 0.030286 / 164 | 0.024744 / 210 | C_cheap_first_cascade |
| {"retries": 0} | 0.032991 / 85 | 0.032634 / 73 | 0.019095 / 340 | 0.023397 / 168 | 0.019571 / 198 | C_cheap_first_cascade |
| {"retries": 2} | 0.032991 / 85 | 0.032783 / 87 | 0.019010 / 333 | 0.023496 / 171 | 0.019490 / 194 | C_cheap_first_cascade |
| {"retries": 5} | 0.032991 / 85 | 0.032795 / 87 | 0.018993 / 333 | 0.023496 / 171 | 0.019490 / 195 | C_cheap_first_cascade |

Distinct lowest-cost policies across the sensitivity grid: ['C_cheap_first_cascade', 'D_adaptive_routing', 'E_double_verified_cascade']. A change of winner along an axis shows that the ranking is assumption-dependent.

## Reading guide

* Lower cost per correct acceptance is not safer: compare the incorrect-acceptance counts.
* Raising `verifier_rho` weakens the benefit of double verification (see axis rows with `verifier_rho`).
* Compare to the closed-form checks in `docs/EVIDENCE.md` (geometric retry cost, false-acceptance product).

## Result classification

| Class | Where |
|---|---|
| SYNTHETIC model results | every table above (illustrative assumptions, seeded, reproducible) |
| MEASURED local performance | the timing line below (machine-dependent) |
| LITERATURE-REPORTED results | none are reproduced here; see `docs/EVIDENCE.md` for citations used only as motivation |

## Prompt-cache sensitivity (SYNTHETIC, closed-form)

Prefix 10,000 tokens, suffix 500, output 1,000; input $3/Mtok, output $15/Mtok; write 1.25x, read 0.10x (placeholder multipliers).

| hit probability | reuses | recommendation | break-even total requests | expected savings (USD) |
|---|---|---|---|---|
| 1 | 1 | USE_CACHE | 1.277777777777777777777777778 | 0.0195 |
| 1 | 3 | USE_CACHE | 1.277777777777777777777777778 | 0.0735 |
| 1 | 10 | USE_CACHE | 1.277777777777777777777777778 | 0.2625 |
| 0.9 | 1 | USE_CACHE | 1.318471337579617834394904459 | 0.01605 |
| 0.9 | 3 | USE_CACHE | 1.318471337579617834394904459 | 0.06315 |
| 0.9 | 10 | USE_CACHE | 1.318471337579617834394904459 | 0.22800 |
| 0.5 | 1 | USE_CACHE | 1.769230769230769230769230769 | 0.00225 |
| 0.5 | 3 | USE_CACHE | 1.769230769230769230769230769 | 0.02175 |
| 0.5 | 10 | USE_CACHE | 1.769230769230769230769230769 | 0.09000 |
| 0.2 | 1 | DO_NOT_CACHE | None | -0.00810 |
| 0.2 | 3 | DO_NOT_CACHE | None | -0.00930 |
| 0.2 | 10 | DO_NOT_CACHE | None | -0.01350 |

## Routing sensitivity (SYNTHETIC)

Cheap model: $0.25/$1.25 per Mtok; strong: $3/$15. Task: 8,000 input / 1,500 output tokens, requires success lower bound 0.9.

| cheap false-accept bound | cheap acceptance A | verification cost (USD) | budget (USD) | decision | selected |
|---|---|---|---|---|---|
| 0.001 | 0.8 | 0 | none | SELECTED | cascade: cheap->strong |
| 0.001 | 0.8 | 0.05 | none | SELECTED | cascade: cheap->strong |
| 0.001 | 0.8 | 0 | 0.05 | SELECTED | single: strong |
| 0.001 | 0.3 | 0 | none | SELECTED | cascade: cheap->strong |
| 0.001 | 0.3 | 0.05 | none | SELECTED | single: strong |
| 0.001 | 0.3 | 0 | 0.05 | SELECTED | single: strong |
| 0.05 | 0.8 | 0 | none | SELECTED | single: strong |
| 0.05 | 0.8 | 0.05 | none | SELECTED | single: strong |
| 0.05 | 0.8 | 0 | 0.05 | SELECTED | single: strong |
| 0.05 | 0.3 | 0 | none | SELECTED | single: strong |
| 0.05 | 0.3 | 0.05 | none | SELECTED | single: strong |
| 0.05 | 0.3 | 0 | 0.05 | SELECTED | single: strong |
| None | 0.8 | 0 | none | SELECTED | single: strong |
| None | 0.8 | 0.05 | none | SELECTED | single: strong |
| None | 0.8 | 0 | 0.05 | SELECTED | single: strong |
| None | 0.3 | 0 | none | SELECTED | single: strong |
| None | 0.3 | 0.05 | none | SELECTED | single: strong |
| None | 0.3 | 0 | 0.05 | SELECTED | single: strong |

Reading: a cascade is chosen only when the cheap model's false-accept bound is *measured and small enough*, its expected cost is lower after verification costs, and the worst-case cost fits the budget. Changing any of these flips the decision, which is the point of the sensitivity sweep.

## Measured local performance (MEASURED, machine-dependent, not part of the reproducibility hash)

Simulation of 20000 tasks x 5 policies took 0.26 s wall-clock on macOS-15.6-arm64-arm-64bit-Mach-O, Python 3.14.7 (single run; use for regression spotting only, not as a benchmark of any model or provider).
