"""Workspace: the .vep state directory (CAS, database, keys) beside the source tree."""
from __future__ import annotations

import time
from pathlib import Path

from .canonical import strict_loads
from .database import Database
from .errors import ObjectNotFound, VepError
from .objects import VEPObject, parse_id
from .storage import CAS


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Workspace:
    STATE_DIR = ".vep"

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.state = self.root / self.STATE_DIR
        if not self.state.is_dir():
            raise VepError(f"{self.root} is not a VEP workspace (run `vep init`)")
        self.cas = CAS(self.state / "cas")
        self.db = Database(self.state / "vep.db")
        self.keys_dir = self.state / "keys"

    @classmethod
    def init(cls, root: str | Path) -> "Workspace":
        root = Path(root).resolve()
        (root / cls.STATE_DIR).mkdir(parents=True, exist_ok=True)
        return cls(root)

    # --- generic immutable object store ---------------------------------
    def put_object(self, obj: VEPObject) -> str:
        digest = self.cas.put(obj.canonical_bytes())
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO objects(id,type,cas_digest) VALUES(?,?,?)",
                      (obj.id, obj.type, digest))
        return obj.id

    def get_object(self, object_id: str, expect_type: str | None = None) -> VEPObject:
        type_name, _ = parse_id(object_id)
        if expect_type and type_name != expect_type:
            raise VepError(f"{object_id} is a {type_name}, expected {expect_type}")
        with self.db.read() as c:
            row = c.execute("SELECT cas_digest FROM objects WHERE id=?", (object_id,)).fetchone()
        if row is None:
            raise ObjectNotFound(f"object {object_id} not registered")
        obj = VEPObject.from_bytes(self.cas.get(row["cas_digest"]))
        if obj.id != object_id:  # identity re-derived from content, never trusted from the index
            from .errors import CorruptObject
            raise CorruptObject(f"stored object does not match id {object_id}")
        return obj
