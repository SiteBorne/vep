"""Local content-addressed storage (CAS) keyed by SHA-256 of the bytes."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from .canonical import HEX64
from .errors import CorruptObject, ObjectNotFound, VepError


class CAS:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.tmp = self.root / "tmp"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.tmp.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not isinstance(digest, str) or not HEX64.match(digest):
            raise VepError(f"invalid digest {digest!r}")  # blocks traversal
        return self.objects / digest[:2] / digest[2:]

    def put(self, data: bytes) -> str:
        if not isinstance(data, (bytes, bytearray)):
            raise VepError("CAS stores bytes only")
        data = bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        path = self._path(digest)
        if path.exists() and self.verify(digest):
            return digest  # duplicate-write elimination
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.tmp)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o444)
            os.replace(tmp, path)  # atomic
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return digest

    def exists(self, digest: str) -> bool:
        return self._path(digest).is_file()

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            raise ObjectNotFound(f"object {digest} not found") from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise CorruptObject(f"object {digest} failed integrity check")
        return data

    def verify(self, digest: str) -> bool:
        try:
            self.get(digest)
        except (ObjectNotFound, CorruptObject):
            return False
        return True
