"""Ed25519 signing of protocol objects in DSSE-style envelopes (PAE-bound payload type)."""
from __future__ import annotations

import base64
import os
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, sha256_hex, strict_loads
from .errors import CorruptObject, VerificationFailed, VepError
from .objects import VEPObject
from .workspace import Workspace, utcnow

PAYLOAD_TYPE = "application/vnd.vep.object+json;v=1"


def _pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + b" " + payload


def key_id(public_raw: bytes) -> str:
    return sha256_hex(public_raw)


def _raw_public(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KeyStore:
    def __init__(self, ws: Workspace):
        self.ws = ws
        self.path = ws.keys_dir / "signing.pem"

    def ensure(self) -> str:
        """Create the signing key on first use; returns the key id. Private bytes never leave this class."""
        self.ws.keys_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.ws.keys_dir, 0o700)
        if not self.path.exists():
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        kid = self.key_id()
        raw = _raw_public(self._load().public_key())
        with self.ws.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO trusted_keys(key_id,public_key_hex,created_at) VALUES(?,?,?)",
                      (kid, raw.hex(), utcnow()))
        return kid

    def _load(self) -> Ed25519PrivateKey:
        if not self.path.exists():
            raise VepError("no signing key; run `vep init`")
        if stat.S_IMODE(self.path.stat().st_mode) & 0o077:
            raise VepError("signing key permissions too open")
        return serialization.load_pem_private_key(self.path.read_bytes(), password=None)

    def key_id(self) -> str:
        return key_id(_raw_public(self._load().public_key()))

    def file_digest(self) -> str:
        return sha256_hex(self.path.read_bytes())

    def sign(self, obj: VEPObject) -> bytes:
        payload = obj.canonical_bytes()
        sig = self._load().sign(_pae(PAYLOAD_TYPE, payload))
        env = {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
               "signatures": [{"keyid": self.key_id(), "sig": base64.b64encode(sig).decode()}]}
        return canonical_bytes(env)


def open_envelope(ws: Workspace, envelope_bytes: bytes, expect_type: str) -> VEPObject:
    """Verify signature against the *workspace-trusted* key registry, then parse the payload."""
    try:
        env = strict_loads(envelope_bytes)
        if set(env) != {"payloadType", "payload", "signatures"} or env["payloadType"] != PAYLOAD_TYPE:
            raise VerificationFailed("malformed envelope")
        payload = base64.b64decode(env["payload"], validate=True)
        sigs = env["signatures"]
        if not isinstance(sigs, list) or len(sigs) != 1:
            raise VerificationFailed("exactly one signature required")
        kid, sig = sigs[0]["keyid"], base64.b64decode(sigs[0]["sig"], validate=True)
    except VerificationFailed:
        raise
    except Exception as exc:
        raise VerificationFailed(f"malformed envelope: {exc}") from exc
    with ws.db.read() as c:
        row = c.execute("SELECT public_key_hex, revoked FROM trusted_keys WHERE key_id=?", (kid,)).fetchone()
    if row is None or row["revoked"]:
        raise VerificationFailed("signing key is not trusted")
    raw = bytes.fromhex(row["public_key_hex"])
    if key_id(raw) != kid:
        raise VerificationFailed("trusted key registry inconsistent")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, _pae(PAYLOAD_TYPE, payload))
    except InvalidSignature:
        raise VerificationFailed("signature invalid") from None
    obj = VEPObject.from_bytes(payload)
    if obj.type != expect_type:
        raise VerificationFailed(f"expected {expect_type}, got {obj.type}")
    return obj


def store_signed(ws: Workspace, obj: VEPObject, signer: KeyStore) -> str:
    """Sign and store; returns envelope CAS digest."""
    ws.put_object(obj)
    return ws.cas.put(signer.sign(obj))


def load_signed(ws: Workspace, envelope_digest: str, expect_type: str) -> VEPObject:
    try:
        data = ws.cas.get(envelope_digest)
    except CorruptObject as exc:
        raise VerificationFailed(str(exc)) from exc
    return open_envelope(ws, data, expect_type)
