"""Synthetic, seeded cost/reliability simulation plus the closed-form results it is checked against.

EVERYTHING HERE IS SIMULATED. Probabilities are illustrative assumptions, not measurements of any
real model. "Best" is only ever relative to the evaluated assumptions, constraints and baselines.
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, replace
from decimal import Decimal

from .errors import SchemaError

MILLION = Decimal(1_000_000)


# ---------------------------------------------------------------- closed-form foundations
def expected_attempts(p: Decimal) -> Decimal:
    """Geometric: expected attempts until first success = 1/p (p in (0,1])."""
    if not (0 < p <= 1):
        raise SchemaError("p must be in (0,1]")
    return 1 / p


def expected_retry_cost(cost_per_attempt: Decimal, p: Decimal, max_attempts: int | None = None) -> Decimal:
    """Unbounded: c/p. Bounded to k attempts: c * (1-(1-p)^k)/p (cost of attempts actually made)."""
    if not (0 < p <= 1):
        raise SchemaError("p must be in (0,1]")
    if max_attempts is None:
        return cost_per_attempt / p
    if max_attempts < 1:
        raise SchemaError("max_attempts >= 1")
    return cost_per_attempt * (1 - (1 - p) ** max_attempts) / p


def false_acceptance_probability(fp1: float, fp2: float, rho: float) -> float:
    """P(incorrect output accepted by two sequential verifiers) with dependence rho in [0,1]:
    P(accept2 | accept1, incorrect) = fp2 + rho*(1 - fp2). rho=0 independent, rho=1 fully dependent."""
    if not all(0 <= x <= 1 for x in (fp1, fp2, rho)):
        raise SchemaError("probabilities must be within [0,1]")
    return fp1 * (fp2 + rho * (1 - fp2))


def littles_law(arrival_rate: Decimal | None = None, wait: Decimal | None = None, in_system: Decimal | None = None) -> Decimal:
    """L = lambda * W; supply exactly two quantities. Valid for a stable system in steady state with
    long-run averages (Little 1961); it says nothing about distributions or transient behaviour."""
    given = [x is not None for x in (arrival_rate, wait, in_system)]
    if sum(given) != 2:
        raise SchemaError("provide exactly two of arrival_rate, wait, in_system")
    if in_system is None:
        return arrival_rate * wait
    if wait is None:
        return in_system / arrival_rate
    return in_system / wait


def max_throughput(workers: int, mean_service_time_s: Decimal) -> Decimal:
    """Stable-queue throughput bound: lambda < c / E[S] (utilization < 1)."""
    if workers < 1 or mean_service_time_s <= 0:
        raise SchemaError("workers>=1 and service time>0")
    return Decimal(workers) / mean_service_time_s


def benjamini_hochberg(pvalues: list[float], q: float) -> list[int]:
    """Indices of hypotheses rejected by the BH step-up procedure at FDR level q (independent or PRDS tests)."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: (pvalues[i], i))
    k = 0
    for rank, i in enumerate(order, start=1):
        if pvalues[i] <= rank * q / m:
            k = rank
    return sorted(order[:k])


# ---------------------------------------------------------------- simulation
@dataclass(frozen=True)
class SimParams:
    n_tasks: int = 20000
    seed: int = 20261019
    difficulty: str = "uniform"          # uniform | hard_skew
    cheap_base: float = 0.80
    cheap_slope: float = 0.70
    strong_base: float = 0.97
    strong_slope: float = 0.25
    verifier_sensitivity: float = 0.98   # P(accept | correct)
    verifier_fp: float = 0.10            # P(accept | incorrect)
    verifier_rho: float = 0.5            # dependence of a second verifier's false accepts on the first's
    retries: int = 2
    router_noise: float = 0.15
    router_threshold: float = 0.5
    in_tokens: int = 4000
    out_tokens: int = 1000
    verify_tokens: int = 500
    cheap_in_price: str = "0.25"         # USD per million tokens (illustrative)
    cheap_out_price: str = "1.25"
    strong_in_price: str = "3.00"
    strong_out_price: str = "15.00"

    def validate(self) -> None:
        for k in ("cheap_base", "strong_base", "verifier_sensitivity", "verifier_fp", "verifier_rho"):
            if not 0 <= getattr(self, k) <= 1:
                raise SchemaError(f"{k} must be within [0,1]")
        if self.n_tasks < 1 or self.retries < 0 or self.difficulty not in ("uniform", "hard_skew"):
            raise SchemaError("invalid simulation parameters")


STRATEGIES = ["A_strong_once", "B_strong_retry", "C_cheap_first_cascade", "D_adaptive_routing", "E_double_verified_cascade"]


class _Acc:
    def __init__(self) -> None:
        self.correct = self.incorrect = self.unaccepted = 0
        self.tokens = 0
        self.cost = Decimal(0)


def _p_correct(base: float, slope: float, d: float) -> float:
    return min(1.0, max(0.0, base - slope * d))


def run_strategies(p: SimParams) -> dict:
    p.validate()
    price = {"cheap": (Decimal(p.cheap_in_price), Decimal(p.cheap_out_price)),
             "strong": (Decimal(p.strong_in_price), Decimal(p.strong_out_price))}
    accs = {s: _Acc() for s in STRATEGIES}

    def charge(acc: _Acc, model: str) -> None:
        pin, pout = price[model]
        acc.tokens += p.in_tokens + p.out_tokens
        acc.cost += (p.in_tokens * pin + p.out_tokens * pout) / MILLION

    def charge_verify(acc: _Acc, model: str) -> None:
        pin, _ = price[model]  # verification priced as input-only tokens at the cheap tier
        acc.tokens += p.verify_tokens
        acc.cost += p.verify_tokens * price["cheap"][0] / MILLION

    def attempt(rng: random.Random, acc: _Acc, model: str, d: float, double: bool) -> tuple[bool, bool]:
        """Return (accepted, correct)."""
        charge(acc, model)
        correct = rng.random() < _p_correct(p.cheap_base if model == "cheap" else p.strong_base,
                                            p.cheap_slope if model == "cheap" else p.strong_slope, d)
        charge_verify(acc, model)
        first = rng.random() < (p.verifier_sensitivity if correct else p.verifier_fp)
        if not double or not first:
            return first, correct
        charge_verify(acc, model)
        pr2 = p.verifier_sensitivity if correct else p.verifier_fp + p.verifier_rho * (1 - p.verifier_fp)
        return rng.random() < pr2, correct

    def finish(acc: _Acc, res: tuple[bool, bool] | None) -> None:
        if res is None or not res[0]:
            acc.unaccepted += 1
        elif res[1]:
            acc.correct += 1
        else:
            acc.incorrect += 1

    for i in range(p.n_tasks):
        rng = random.Random(f"{p.seed}:{i}")
        d = rng.random() if p.difficulty == "uniform" else rng.betavariate(3, 1.5)
        est = min(1.0, max(0.0, d + rng.gauss(0, p.router_noise)))
        # A: strong once
        finish(accs["A_strong_once"], attempt(rng, accs["A_strong_once"], "strong", d, False))
        # B: strong with retries after rejection
        res = None
        for _ in range(p.retries + 1):
            res = attempt(rng, accs["B_strong_retry"], "strong", d, False)
            if res[0]:
                break
        finish(accs["B_strong_retry"], res)

        def cascade(name: str, double: bool, first_model_cheap: bool = True) -> None:
            acc = accs[name]
            res = attempt(rng, acc, "cheap", d, double) if first_model_cheap else (False, False)
            if not res[0]:
                res = attempt(rng, acc, "strong", d, double)
            finish(acc, res)
        cascade("C_cheap_first_cascade", False)
        # D: adaptive — easy-looking tasks go cheap-first, hard-looking go straight to strong
        if est < p.router_threshold:
            cascade("D_adaptive_routing", False)
        else:
            finish(accs["D_adaptive_routing"], attempt(rng, accs["D_adaptive_routing"], "strong", d, False))
        cascade("E_double_verified_cascade", True)

    out = {}
    for s, a in accs.items():
        accepted_correct = a.correct
        out[s] = {
            "correctly_accepted_fraction": format(a.correct / p.n_tasks, ".6f"),
            "incorrect_acceptances": a.incorrect,
            "incorrect_acceptance_fraction": format(a.incorrect / p.n_tasks, ".6f"),
            "unaccepted_tasks": a.unaccepted,
            "total_tokens": a.tokens,
            "total_cost_usd": format(a.cost.quantize(Decimal("0.000001")), "f"),
            "cost_per_correct_acceptance_usd": None if accepted_correct == 0 else format(
                (a.cost / accepted_correct).quantize(Decimal("0.000001")), "f"),
        }
    return out


def sensitivity(base: SimParams) -> list[dict]:
    rows = []
    for fp in (0.02, 0.10, 0.30):
        for rho in (0.0, 0.5, 1.0):
            q = replace(base, verifier_fp=fp, verifier_rho=rho)
            rows.append({"axis": {"verifier_fp": fp, "verifier_rho": rho}, "results": run_strategies(q)})
    for ratio in ("2", "12", "60"):
        q = replace(base, strong_in_price=str(Decimal(base.cheap_in_price) * Decimal(ratio)),
                    strong_out_price=str(Decimal(base.cheap_out_price) * Decimal(ratio)))
        rows.append({"axis": {"strong_to_cheap_price_ratio": ratio}, "results": run_strategies(q)})
    for dist in ("uniform", "hard_skew"):
        rows.append({"axis": {"difficulty": dist}, "results": run_strategies(replace(base, difficulty=dist))})
    for r in (0, 2, 5):
        rows.append({"axis": {"retries": r}, "results": run_strategies(replace(base, retries=r))})
    return rows


def run_report(p: SimParams, with_sensitivity: bool = True) -> dict:
    report = {
        "label": "SIMULATED - synthetic assumptions, not measurements of real models",
        "params": p.__dict__ | {}, "results": run_strategies(p),
        "assumptions": [
            "task difficulty d in [0,1]; P(correct) is linear in d with the stated base/slope",
            "verifier accepts correct output with prob sensitivity and incorrect with prob fp",
            "second verifier's false accept prob = fp + rho*(1-fp) given the first accepted an incorrect output",
            "adaptive routing observes difficulty with Gaussian noise; thresholded",
            "prices are illustrative placeholders, not any vendor's pricing",
            "no policy here is claimed globally optimal; comparisons hold only under these assumptions"],
    }
    if with_sensitivity:
        small = replace(p, n_tasks=max(1, p.n_tasks // 4))
        report["sensitivity_n_tasks"] = small.n_tasks
        report["sensitivity"] = sensitivity(small)
    report["result_sha256"] = hashlib.sha256(json.dumps(
        {k: v for k, v in report.items()}, sort_keys=True, default=str).encode()).hexdigest()
    return report
