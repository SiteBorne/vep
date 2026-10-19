"""Deterministic prompt-cache economics. Returns a recommendation, never an invented cache hit."""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .errors import SchemaError
from .routing import D, prob

MILLION = Decimal(1_000_000)


@dataclass(frozen=True)
class CacheInputs:
    prefix_tokens: int
    suffix_tokens: int
    output_tokens: int
    ordinary_input_price: Decimal      # USD per million tokens
    output_price: Decimal              # USD per million tokens
    cache_write_multiplier: Decimal    # write price / ordinary input price
    cache_read_multiplier: Decimal     # read price / ordinary input price
    expected_reuses: int               # additional requests that could reuse the prefix
    cache_lifetime_s: Decimal | None = None
    request_interval_s: Decimal | None = None
    estimated_hit_probability: Decimal = Decimal(1)

    @staticmethod
    def build(**kw: Any) -> "CacheInputs":
        for k in ("prefix_tokens", "suffix_tokens", "output_tokens", "expected_reuses"):
            if isinstance(kw.get(k), bool) or not isinstance(kw.get(k), int) or kw[k] < 0:
                raise SchemaError(f"{k} must be a non-negative integer")
        ci = CacheInputs(
            kw["prefix_tokens"], kw["suffix_tokens"], kw["output_tokens"],
            D(kw["ordinary_input_price"], "ordinary_input_price"), D(kw.get("output_price", "0"), "output_price"),
            D(kw["cache_write_multiplier"], "cache_write_multiplier"),
            D(kw["cache_read_multiplier"], "cache_read_multiplier"), kw["expected_reuses"],
            None if kw.get("cache_lifetime_s") is None else D(kw["cache_lifetime_s"], "cache_lifetime_s"),
            None if kw.get("request_interval_s") is None else D(kw["request_interval_s"], "request_interval_s"),
            prob(kw.get("estimated_hit_probability", "1"), "estimated_hit_probability"))
        if min(ci.ordinary_input_price, ci.output_price, ci.cache_write_multiplier, ci.cache_read_multiplier) < 0:
            raise SchemaError("prices and multipliers must be non-negative")
        if ci.cache_read_multiplier > 1:
            raise SchemaError("cache_read_multiplier > 1 is outside the supported model (read dearer than ordinary input)")
        return ci


def break_even_requests(write_mult: Decimal, read_mult: Decimal) -> Decimal | None:
    """Smallest real n (total requests including the first write) with caching strictly cheaper.

    cached = w + (n-1)r   vs   uncached = n   =>   n > (w - r)/(1 - r)   for r < 1.
    Returns None when caching can never win (r == 1 and w >= 1). The strict inequality means that
    at exactly n == result the two options cost the same.
    """
    if write_mult < 0 or read_mult < 0:
        raise SchemaError("multipliers must be non-negative")
    if read_mult > 1:
        raise SchemaError("read multiplier above 1 unsupported")
    denom = Decimal(1) - read_mult
    if denom == 0:
        return Decimal(0) if write_mult < 1 else None
    return (write_mult - read_mult) / denom


def plan(ci: CacheInputs) -> dict:
    h = ci.estimated_hit_probability
    notes = ["VEP cannot control provider-side cache behavior; hit probability is an input assumption."]
    if ci.cache_lifetime_s is not None and ci.request_interval_s is not None \
            and ci.request_interval_s > ci.cache_lifetime_s:
        h = Decimal(0)
        notes.append("request interval exceeds cache lifetime: effective hit probability set to 0")
    w, r = ci.cache_write_multiplier, ci.cache_read_multiplier
    m = h * r + (1 - h) * w  # expected multiplier on a reuse request (a miss re-writes the prefix)
    pin, pout = ci.ordinary_input_price, ci.output_price
    n = ci.expected_reuses + 1
    out_cost = ci.output_tokens * pout / MILLION
    suffix_cost = ci.suffix_tokens * pin / MILLION
    pre = ci.prefix_tokens * pin / MILLION
    uncached = n * (pre + suffix_cost + out_cost)
    cached = (w * pre + suffix_cost + out_cost) + ci.expected_reuses * (m * pre + suffix_cost + out_cost)
    # break-even uses the effective multiplier m; with h == 1 this is the closed form (w-r)/(1-r)
    if m > 1 or (m == 1 and w >= 1):
        be = None
    else:
        be = break_even_requests(w, m)
    if cached < uncached:
        rec = "USE_CACHE"
    elif cached > uncached:
        rec = "DO_NOT_CACHE"
    else:
        rec = "INDIFFERENT"
    f = lambda x: format(x, "f")
    return {"recommendation": rec, "total_requests": n, "uncached_cost_usd": f(uncached),
            "cached_expected_cost_usd": f(cached), "expected_savings_usd": f(uncached - cached),
            "effective_hit_probability": f(h), "effective_reuse_multiplier": f(m),
            "break_even_total_requests": None if be is None else f(be),
            "break_even_rule": "caching strictly cheaper iff total_requests > break_even_total_requests",
            "notes": notes}
