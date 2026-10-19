"""Offline routing policy engine: lowest expected-cost eligible policy under declared constraints.

All inputs are supplied (measured, simulated or supplied-by-operator) and labeled. Model reputation
is not an input. No model is called.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from .errors import SchemaError

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
MILLION = Decimal(1_000_000)


def D(v: Any, name: str = "value") -> Decimal:
    if isinstance(v, float):
        raise SchemaError(f"{name}: floats not permitted; pass a string or int")
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        raise SchemaError(f"{name}: invalid decimal {v!r}") from None
    if not d.is_finite():
        raise SchemaError(f"{name}: must be finite")
    return d


def prob(v: Any, name: str) -> Decimal:
    d = D(v, name)
    if not (Decimal(0) <= d <= Decimal(1)):
        raise SchemaError(f"{name}: probability must be within [0,1]")
    return d


@dataclass(frozen=True)
class ModelOption:
    name: str
    price_in_per_m: Decimal
    price_out_per_m: Decimal
    context_capacity: int
    capabilities: frozenset
    acceptance_estimate: Decimal      # P(output is accepted by verification)
    success_lower_bound: Decimal      # lower confidence bound on P(accepted output is correct-and-accepted)
    latency_s: Decimal
    max_risk: str
    evidence_source: str              # measured | simulated | supplied
    verification_cost: Decimal = Decimal(0)   # USD per attempt
    false_accept_upper: Decimal | None = None  # upper bound on P(incorrect output accepted); None = unmeasured

    @staticmethod
    def from_dict(d: dict) -> "ModelOption":
        try:
            opt = ModelOption(
                name=d["name"], price_in_per_m=D(d["price_in_per_m"], "price_in_per_m"),
                price_out_per_m=D(d["price_out_per_m"], "price_out_per_m"),
                context_capacity=int(d["context_capacity"]), capabilities=frozenset(d.get("capabilities", [])),
                acceptance_estimate=prob(d["acceptance_estimate"], "acceptance_estimate"),
                success_lower_bound=prob(d["success_lower_bound"], "success_lower_bound"),
                latency_s=D(d["latency_s"], "latency_s"), max_risk=d["max_risk"],
                evidence_source=d["evidence_source"],
                verification_cost=D(d.get("verification_cost", "0"), "verification_cost"),
                false_accept_upper=None if d.get("false_accept_upper") is None
                else prob(d["false_accept_upper"], "false_accept_upper"))
        except KeyError as exc:
            raise SchemaError(f"model option missing field {exc}") from None
        if opt.max_risk not in RISK_ORDER or opt.evidence_source not in ("measured", "simulated", "supplied"):
            raise SchemaError("invalid max_risk or evidence_source")
        if opt.price_in_per_m < 0 or opt.price_out_per_m < 0 or opt.verification_cost < 0 or opt.latency_s < 0:
            raise SchemaError("prices, latency and verification cost must be non-negative")
        return opt


@dataclass(frozen=True)
class Task:
    input_tokens: int
    output_tokens: int
    required_capabilities: frozenset = frozenset()
    min_success_lower_bound: Decimal = Decimal("0.9")
    max_latency_s: Decimal | None = None
    risk: str = "low"
    budget_available: Decimal | None = None
    max_false_accept: Decimal = Decimal("0.01")
    allowed_sources: frozenset = frozenset({"measured"})

    @staticmethod
    def from_dict(d: dict) -> "Task":
        t = Task(
            input_tokens=int(d["input_tokens"]), output_tokens=int(d["output_tokens"]),
            required_capabilities=frozenset(d.get("required_capabilities", [])),
            min_success_lower_bound=prob(d.get("min_success_lower_bound", "0.9"), "min_success_lower_bound"),
            max_latency_s=None if d.get("max_latency_s") is None else D(d["max_latency_s"], "max_latency_s"),
            risk=d.get("risk", "low"),
            budget_available=None if d.get("budget_available") is None else D(d["budget_available"], "budget"),
            max_false_accept=prob(d.get("max_false_accept", "0.01"), "max_false_accept"),
            allowed_sources=frozenset(d.get("allowed_sources", ["measured"])))
        if t.risk not in RISK_ORDER or t.input_tokens < 0 or t.output_tokens < 0:
            raise SchemaError("invalid task")
        return t


def request_cost(m: ModelOption, t: Task) -> Decimal:
    return (m.price_in_per_m * t.input_tokens + m.price_out_per_m * t.output_tokens) / MILLION


def attempt_cost(m: ModelOption, t: Task) -> Decimal:
    return request_cost(m, t) + m.verification_cost


def cascade_expected_cost(c_cheap: Decimal, a_cheap: Decimal, c_strong: Decimal) -> Decimal:
    """E[C] = C_cheap + (1 - A_cheap) * C_strong, with verification costs included in each C."""
    return c_cheap + (Decimal(1) - a_cheap) * c_strong


def ineligible_reasons(m: ModelOption, t: Task) -> list[str]:
    r = []
    if t.input_tokens + t.output_tokens > m.context_capacity:
        r.append("context capacity exceeded")
    if not t.required_capabilities <= m.capabilities:
        r.append("missing capabilities " + ",".join(sorted(t.required_capabilities - m.capabilities)))
    if RISK_ORDER[t.risk] > RISK_ORDER[m.max_risk]:
        r.append("task risk exceeds model's declared maximum")
    if m.evidence_source not in t.allowed_sources:
        r.append(f"evidence source {m.evidence_source!r} not allowed for this task")
    if t.max_latency_s is not None and m.latency_s > t.max_latency_s:
        r.append("latency exceeds limit")
    return r


@dataclass
class Choice:
    kind: str
    models: list[str]
    expected_cost: Decimal
    worst_case_cost: Decimal
    quality_lower_bound: Decimal
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "models": self.models, "expected_cost_usd": format(self.expected_cost, "f"),
                "worst_case_cost_usd": format(self.worst_case_cost, "f"),
                "quality_lower_bound": format(self.quality_lower_bound, "f"), "notes": self.notes}


def select(models: list[ModelOption], task: Task) -> dict:
    """Choose the cheapest eligible policy; abstain (selected=None) if none qualifies."""
    rejected: dict[str, list[str]] = {}
    choices: list[Choice] = []
    base_ok: list[ModelOption] = []
    for m in sorted(models, key=lambda x: x.name):
        why = ineligible_reasons(m, task)
        if why:
            rejected[m.name] = why
        else:
            base_ok.append(m)
    sources = lambda ms: sorted({m.evidence_source for m in ms})
    for m in base_ok:
        if m.success_lower_bound < task.min_success_lower_bound:
            rejected.setdefault(m.name + "[single]", []).append("success lower bound below requirement")
            continue
        c = attempt_cost(m, task)
        choices.append(Choice("single", [m.name], c, c, m.success_lower_bound,
                              [f"evidence: {sources([m])}"]))
    strong_pool = [m for m in base_ok if m.success_lower_bound >= task.min_success_lower_bound]
    for cheap in base_ok:
        for strong in strong_pool:
            if cheap.name == strong.name or attempt_cost(cheap, task) >= attempt_cost(strong, task):
                continue
            tag = f"{cheap.name}->{strong.name}[cascade]"
            if cheap.false_accept_upper is None:
                rejected[tag] = ["cheap model's incorrect-acceptance rate is unmeasured; safety not established"]
                continue
            if cheap.false_accept_upper > task.max_false_accept:
                rejected[tag] = ["cheap model's false-accept upper bound exceeds allowed maximum"]
                continue
            cc, cs = attempt_cost(cheap, task), attempt_cost(strong, task)
            exp = cascade_expected_cost(cc, cheap.acceptance_estimate, cs)
            choices.append(Choice("cascade", [cheap.name, strong.name], exp, cc + cs, strong.success_lower_bound,
                                  [f"A_cheap={cheap.acceptance_estimate} (verified acceptance probability)",
                                   f"false-accept upper bound {cheap.false_accept_upper}",
                                   "cascade does not claim to be safer; incorrect acceptance is bounded only by measurement",
                                   f"evidence: {sources([cheap, strong])}"]))
    if task.budget_available is not None:
        kept = []
        for ch in choices:
            if ch.worst_case_cost > task.budget_available:
                rejected[f"{'->'.join(ch.models)}[{ch.kind}]"] = ["worst-case cost exceeds available budget"]
            else:
                kept.append(ch)
        choices = kept
    choices.sort(key=lambda c: (c.expected_cost, c.worst_case_cost, c.kind, c.models))
    return {"selected": choices[0].to_dict() if choices else None,
            "ranked": [c.to_dict() for c in choices], "rejected": rejected,
            "decision": "SELECTED" if choices else "ABSTAIN",
            "note": "Inputs are caller-supplied; this engine performs no model calls and asserts no benchmark results."}
