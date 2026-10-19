"""Objectives: bind a goal to a trusted base snapshot and a frozen policy."""
from __future__ import annotations

from .errors import SchemaError
from .objects import VEPObject
from .policies import load_policy
from .workspace import Workspace, utcnow


def create_objective(ws: Workspace, title: str, description: str, base_snapshot_id: str,
                     policy_id: str, created_by: str = "operator") -> VEPObject:
    ws.get_object(base_snapshot_id, "Snapshot")
    load_policy(ws, policy_id)  # validates
    obj = VEPObject.create("Objective", {
        "title": title, "description": description, "base_snapshot_id": base_snapshot_id,
        "policy_id": policy_id, "created_by": created_by, "created_at": utcnow()})
    ws.put_object(obj)
    return obj


def get_objective(ws: Workspace, objective_id: str) -> VEPObject:
    return ws.get_object(objective_id, "Objective")


def list_objectives(ws: Workspace) -> list[str]:
    with ws.db.read() as c:
        return [r["id"] for r in c.execute("SELECT id FROM objects WHERE type='Objective' ORDER BY id")]


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise SchemaError(msg)
