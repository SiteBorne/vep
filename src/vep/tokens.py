"""Provider-independent token accounting. Usage is supplied, never fabricated."""
from __future__ import annotations

import sqlite3
from decimal import Decimal, InvalidOperation
from typing import Any

from .budgets import settle, to_micro
from .errors import SchemaError
from .objects import VEPObject
from .workspace import Workspace

PRICE_KEYS = ("input", "cached_input", "cache_write", "output")
TOKEN_KEYS = ("ordinary_input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens")


def _dec(v: Any, name: str) -> Decimal:
    if isinstance(v, float):
        raise SchemaError(f"{name}: floats not permitted for money")
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        raise SchemaError(f"{name}: invalid decimal") from None
    if not d.is_finite() or d < 0:
        raise SchemaError(f"{name}: must be finite and non-negative")
    return d


def compute_cost(usage: dict, prices_per_million: dict, other_charges: Any = "0") -> Decimal:
    """C_llm = (Tu*Pu + Tr*Pr + Tw*Pw + To*Po)/1e6 + C_other.

    Reasoning tokens are a subset of billed output tokens and are never added again.
    """
    p = {k: _dec(prices_per_million[k], f"price.{k}") for k in PRICE_KEYS}
    tu, tr, tw, to = (usage[k] for k in TOKEN_KEYS)
    return (tu * p["input"] + tr * p["cached_input"] + tw * p["cache_write"] + to * p["output"]) / Decimal(1_000_000) \
        + _dec(other_charges, "other_provider_charges")


def make_receipt(*, provider: str, model: str, pricing_version: str, candidate_id: str, attempt: int,
                 ordinary_input_tokens: int, cached_input_tokens: int, cache_write_tokens: int,
                 output_tokens: int, reasoning_tokens_in_output: int, prices_per_million: dict,
                 usage_source: str, idempotency_key: str, other_provider_charges: Any = "0",
                 context_id: str | None = None, status: str = "RECORDED") -> VEPObject:
    if usage_source is None:
        raise SchemaError("usage_source is mandatory (provider_reported | simulated | local_estimate)")
    usage = {"ordinary_input_tokens": ordinary_input_tokens, "cached_input_tokens": cached_input_tokens,
             "cache_write_tokens": cache_write_tokens, "output_tokens": output_tokens}
    for k, v in {**usage, "reasoning_tokens_in_output": reasoning_tokens_in_output}.items():
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise SchemaError(f"{k} must be a non-negative integer")
    if reasoning_tokens_in_output > output_tokens:
        raise SchemaError("reasoning_tokens_in_output cannot exceed output_tokens (they are included in output)")
    prices = {k: str(_dec(prices_per_million[k], k)) for k in PRICE_KEYS}
    cost = compute_cost(usage, prices, other_provider_charges)
    fields = {"provider": provider, "model": model, "pricing_version": pricing_version,
              "candidate_id": candidate_id, "attempt": attempt, **usage,
              "reasoning_tokens_in_output": reasoning_tokens_in_output,
              "other_provider_charges": str(_dec(other_provider_charges, "other")),
              "prices_per_million": prices, "usage_source": usage_source, "cost_usd": format(cost, "f"),
              "status": status, "idempotency_key": idempotency_key}
    if context_id:
        fields["context_id"] = context_id
    return VEPObject.create("TokenReceipt", fields)


def record_receipt(ws: Workspace, receipt: VEPObject, reservation_key: str | None = None) -> dict:
    """Persist a receipt idempotently; optionally settle a budget reservation atomically."""
    ws.get_object(receipt["candidate_id"], "Candidate")
    cost_micro = to_micro(receipt["cost_usd"], rounding="ceil")
    with ws.db.tx() as c:
        row = c.execute("SELECT id FROM token_receipts WHERE idempotency_key=?",
                        (receipt["idempotency_key"],)).fetchone()
        if row:
            if row["id"] != receipt.id:
                raise SchemaError("idempotency key reused with a different receipt")
            existing = True
        else:
            existing = False
            digest = ws.cas.put(receipt.canonical_bytes())
            c.execute("INSERT INTO objects(id,type,cas_digest) VALUES(?,?,?) ON CONFLICT DO NOTHING",
                      (receipt.id, receipt.type, digest))
            c.execute("INSERT INTO token_receipts(id,candidate_id,attempt,idempotency_key,cost_micro_usd,cas_digest)"
                      " VALUES(?,?,?,?,?,?)", (receipt.id, receipt["candidate_id"], receipt["attempt"],
                                               receipt["idempotency_key"], str(cost_micro), digest))
        settled = None
        if reservation_key:
            settled = settle(ws, reservation_key, Decimal(cost_micro) / Decimal(1_000_000),
                             f"receipt:{receipt.id}", conn=c)
    return {"receipt_id": receipt.id, "cost_usd": receipt["cost_usd"], "duplicate": existing,
            "reservation": settled}


def totals(ws: Workspace, candidate_id: str) -> dict:
    with ws.db.read() as c:
        rows = c.execute("SELECT cost_micro_usd FROM token_receipts WHERE candidate_id=?", (candidate_id,)).fetchall()
    micro = sum(int(r["cost_micro_usd"]) for r in rows)
    return {"candidate_id": candidate_id, "receipts": len(rows), "cost_usd": format(Decimal(micro) / Decimal(1_000_000), "f")}
