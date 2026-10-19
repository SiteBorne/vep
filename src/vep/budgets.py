"""Hierarchical transactional budgets (organization > project > objective > candidate > operation).

Money is stored as integer micro-USD (1 USD = 1_000_000) and exposed as Decimal.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any

from .errors import BudgetError
from .workspace import Workspace, utcnow

RANK = {"organization": 0, "project": 1, "objective": 2, "candidate": 3, "operation": 4}
MICRO = Decimal(1_000_000)
MAX_MICRO = 2**62  # headroom below SQLite's signed 64-bit INTEGER for sums


def to_micro(amount: Any, rounding: str | None = None) -> int:
    if isinstance(amount, float):
        raise BudgetError("floats are not permitted for money; use Decimal or str")
    try:
        d = Decimal(str(amount))
    except InvalidOperation:
        raise BudgetError(f"invalid amount {amount!r}") from None
    if not d.is_finite():
        raise BudgetError("amount must be finite")
    scaled = d * MICRO
    if scaled != scaled.to_integral_value():
        if rounding != "ceil":
            raise BudgetError("amount has sub-micro-dollar precision")
        scaled = scaled.to_integral_value(rounding=ROUND_CEILING)
    if abs(scaled) > MAX_MICRO:
        raise BudgetError("amount exceeds the supported range")
    return int(scaled)


def from_micro(micro: int) -> Decimal:
    return Decimal(micro) / MICRO


@contextmanager
def _tx(ws: Workspace, conn: sqlite3.Connection | None):
    if conn is not None:
        yield conn
    else:
        with ws.db.tx() as c:
            yield c


def _ledger(c, account_id, key, event, amount, detail=""):
    c.execute("INSERT INTO ledger(account_id,reservation_key,event,amount_micro,detail,at) VALUES(?,?,?,?,?,?)",
              (account_id, key, event, amount, detail, utcnow()))


def create_account(ws: Workspace, account_id: str, kind: str, limit: Any, parent_id: str | None = None) -> dict:
    if kind not in RANK:
        raise BudgetError(f"unknown account kind {kind!r}")
    limit_micro = to_micro(limit)
    if limit_micro < 0:
        raise BudgetError("limit must be non-negative")
    with ws.db.tx() as c:
        row = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row:
            if (row["kind"], row["parent_id"], row["limit_micro"]) != (kind, parent_id, limit_micro):
                raise BudgetError(f"account {account_id} exists with different parameters")
            return dict(row)
        if parent_id is not None:
            p = c.execute("SELECT kind FROM accounts WHERE id=?", (parent_id,)).fetchone()
            if p is None:
                raise BudgetError(f"unknown parent account {parent_id}")
            if RANK[p["kind"]] >= RANK[kind]:
                raise BudgetError(f"{kind} cannot be a child of {p['kind']}")
        c.execute("INSERT INTO accounts(id,kind,parent_id,limit_micro) VALUES(?,?,?,?)",
                  (account_id, kind, parent_id, limit_micro))
        _ledger(c, account_id, None, "ACCOUNT_CREATED", limit_micro, kind)
        return {"id": account_id, "kind": kind, "parent_id": parent_id, "limit_micro": limit_micro}


def _chain(c, account_id: str) -> list[dict]:
    out, cur = [], account_id
    while cur is not None:
        row = c.execute("SELECT * FROM accounts WHERE id=?", (cur,)).fetchone()
        if row is None:
            raise BudgetError(f"unknown account {cur}")
        out.append(dict(row))
        cur = row["parent_id"]
    return out


USED_SQL = """SELECT COALESCE(SUM(CASE r.state WHEN 'RESERVED' THEN r.amount_micro
  WHEN 'UNCERTAIN' THEN r.amount_micro WHEN 'SETTLED' THEN r.actual_micro ELSE 0 END),0) AS used
  FROM reservation_scope s JOIN reservations r ON r.key=s.reservation_key WHERE s.account_id=?"""


def _used(c, account_id: str) -> int:
    return c.execute(USED_SQL, (account_id,)).fetchone()["used"]


def reserve(ws: Workspace, account_id: str, amount: Any, key: str, conn: sqlite3.Connection | None = None) -> dict:
    micro = to_micro(amount)
    if micro <= 0:
        raise BudgetError("reservation must be positive")
    if not key:
        raise BudgetError("idempotency key required")
    with _tx(ws, conn) as c:
        ex = c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone()
        if ex:
            if ex["account_id"] != account_id or ex["amount_micro"] != micro:
                raise BudgetError(f"idempotency key {key!r} reused with different parameters")
            return dict(ex)
        for acct in _chain(c, account_id):
            avail = acct["limit_micro"] - _used(c, acct["id"])
            if micro > avail:
                raise BudgetError(f"insufficient budget in {acct['id']}: need {micro}, available {max(avail, 0)} micro-USD")
        c.execute("INSERT INTO reservations(key,account_id,amount_micro,state) VALUES(?,?,?, 'RESERVED')",
                  (key, account_id, micro))
        for acct in _chain(c, account_id):
            c.execute("INSERT INTO reservation_scope(reservation_key,account_id) VALUES(?,?)", (key, acct["id"]))
        _ledger(c, account_id, key, "RESERVE", micro)
        return dict(c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone())


def settle(ws: Workspace, key: str, actual: Any, settle_key: str, conn: sqlite3.Connection | None = None) -> dict:
    actual_micro = to_micro(actual, rounding="ceil")
    if actual_micro < 0:
        raise BudgetError("actual must be non-negative")
    with _tx(ws, conn) as c:
        r = c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone()
        if r is None:
            raise BudgetError(f"unknown reservation {key}")
        if r["state"] == "SETTLED":
            if r["settle_key"] == settle_key and r["actual_micro"] == actual_micro:
                return dict(r)  # identical repeat: no second charge
            raise BudgetError("conflicting settlement for an already-settled reservation")
        if r["state"] == "RELEASED":
            raise BudgetError("reservation already released")
        overrun = max(0, actual_micro - r["amount_micro"])
        c.execute("UPDATE reservations SET state='SETTLED', actual_micro=?, settle_key=?, overrun_micro=? WHERE key=?",
                  (actual_micro, settle_key, overrun, key))
        _ledger(c, r["account_id"], key, "SETTLE", actual_micro, f"overrun={overrun}" if overrun else "")
        if overrun:
            _ledger(c, r["account_id"], key, "OVERRUN", overrun, "actual exceeded reservation")
        return dict(c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone())


def release(ws: Workspace, key: str, conn: sqlite3.Connection | None = None) -> dict:
    with _tx(ws, conn) as c:
        r = c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone()
        if r is None:
            raise BudgetError(f"unknown reservation {key}")
        if r["state"] == "RELEASED":
            return dict(r)
        if r["state"] == "SETTLED":
            raise BudgetError("cannot release a settled reservation")
        c.execute("UPDATE reservations SET state='RELEASED' WHERE key=?", (key,))
        _ledger(c, r["account_id"], key, "RELEASE", r["amount_micro"])
        return dict(c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone())


def mark_uncertain(ws: Workspace, key: str) -> dict:
    """Operation outcome unknown: keep the funds held, tracked separately until resolved."""
    with ws.db.tx() as c:
        r = c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone()
        if r is None or r["state"] not in ("RESERVED", "UNCERTAIN"):
            raise BudgetError("only an open reservation can be marked uncertain")
        c.execute("UPDATE reservations SET state='UNCERTAIN' WHERE key=?", (key,))
        _ledger(c, r["account_id"], key, "UNCERTAIN", r["amount_micro"])
        return dict(c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone())


def get_reservation(ws: Workspace, key: str) -> dict | None:
    with ws.db.read() as c:
        r = c.execute("SELECT * FROM reservations WHERE key=?", (key,)).fetchone()
    return dict(r) if r else None


def report(ws: Workspace, account_id: str) -> dict:
    with ws.db.read() as c:
        acct = c.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if acct is None:
            raise BudgetError(f"unknown account {account_id}")
        parts = {}
        for state in ("RESERVED", "SETTLED", "UNCERTAIN"):
            parts[state] = c.execute(
                "SELECT COALESCE(SUM(CASE r.state WHEN 'SETTLED' THEN r.actual_micro ELSE r.amount_micro END),0) AS s"
                " FROM reservation_scope s JOIN reservations r ON r.key=s.reservation_key"
                " WHERE s.account_id=? AND r.state=?", (account_id, state)).fetchone()["s"]
        overrun = c.execute(
            "SELECT COALESCE(SUM(r.overrun_micro),0) AS s FROM reservation_scope s JOIN reservations r"
            " ON r.key=s.reservation_key WHERE s.account_id=?", (account_id,)).fetchone()["s"]
        chain = _chain(c, account_id)
        avail = min(a["limit_micro"] - _used(c, a["id"]) for a in chain)
    return {"account": account_id, "kind": acct["kind"], "limit": str(from_micro(acct["limit_micro"])),
            "reserved": str(from_micro(parts["RESERVED"])), "settled": str(from_micro(parts["SETTLED"])),
            "uncertain": str(from_micro(parts["UNCERTAIN"])), "overrun": str(from_micro(overrun)),
            "available": str(from_micro(max(avail, 0))), "overspent": avail < 0}


def available(ws: Workspace, account_id: str) -> Decimal:
    return Decimal(report(ws, account_id)["available"])


def history(ws: Workspace, account_id: str) -> list[dict]:
    with ws.db.read() as c:
        rows = c.execute(
            "SELECT * FROM ledger WHERE account_id=? OR reservation_key IN"
            " (SELECT reservation_key FROM reservation_scope WHERE account_id=?) ORDER BY seq",
            (account_id, account_id)).fetchall()
    return [dict(r) for r in rows]
