"""Generate the frozen conformance suite conformance/vectors/suite-1.0.json (deterministic).

Run:  python scripts/gen_conformance_vectors.py          (writes the file)
      python scripts/gen_conformance_vectors.py --check  (exit 1 if the committed file differs)

Keys are derived from fixed seeds (Ed25519 signing is deterministic), so output is byte-stable. Expected results
are asserted here against hand-derived intent, not merely copied from whatever the reference produced.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from vep import conformance, objects  # noqa: E402
from vep.canonical import canonical_bytes, sha256_hex  # noqa: E402
from vep.evidence import PAYLOAD_TYPE, _pae  # noqa: E402
from vep.objects import VEPObject  # noqa: E402

OUT = ROOT / "conformance" / "vectors" / "suite-1.0.json"


def h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def key(label: str):
    k = Ed25519PrivateKey.from_seed(hashlib.sha256(label.encode()).digest()) if hasattr(Ed25519PrivateKey, "from_seed") \
        else Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return k, raw, sha256_hex(raw)


KA, RAW_A, KID_A = key("vep-conformance-key-A")
KB, RAW_B, KID_B = key("vep-conformance-key-B")


def sign_payload(payload: bytes, k=KA, kid=KID_A, payload_type=PAYLOAD_TYPE) -> dict:
    sig = k.sign(_pae(PAYLOAD_TYPE, payload))
    return {"payloadType": payload_type, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}


def sign_obj(obj: VEPObject, **kw) -> dict:
    return sign_payload(obj.canonical_bytes(), **kw)


IDS = {"cand": "cand-" + h("cand"), "obj": "obj-" + h("obj"), "snap": "snap-" + h("snap"), "pol": "pol-" + h("pol"),
       "act": "act-" + h("act")}


def evidence_fields(**over) -> dict:
    f = {"candidate_id": IDS["cand"], "objective_id": IDS["obj"], "snapshot_id": IDS["snap"], "policy_id": IDS["pol"],
         "action_id": IDS["act"], "runner_digest": h("runner"), "argv": ["<protected-runner>", "unittest"], "exit_code": 0,
         "verdict": "PASS", "tests_discovered": 3, "tests_run": 3, "tests_passed": 3, "tests_failed": 0,
         "tests_skipped": 0, "executed_ids_digest": h("ids"), "stdout_digest": h("out"), "stderr_digest": h("err"),
         "staged_tree_snapshot_id": IDS["snap"], "isolation": "NONE_TRUSTED_LOCAL",
         "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:01Z", "budget_reservation": "eval:x",
         "trust_level": "TRUSTED_LOCAL", "evaluator_id": "vep-local-evaluator/0.5.0/TRUSTED_LOCAL",
         "execution_environment": {"kind": "host-subprocess"}}
    f.update(over)
    return f


def cert_fields(ev_obj: VEPObject, ev_env: dict, **over) -> dict:
    f = {"candidate_id": IDS["cand"], "objective_id": IDS["obj"], "snapshot_id": IDS["snap"], "policy_id": IDS["pol"],
         "evidence_id": ev_obj.id, "evidence_envelope_digest": sha256_hex(canonical_bytes(ev_env)),
         "issuer_key_id": KID_A, "issued_at": "2026-01-01T00:00:02Z", "trust_level": "TRUSTED_LOCAL",
         "evaluator_id": "vep-local-evaluator/0.5.0/TRUSTED_LOCAL"}
    f.update(over)
    return f


def bundle(cert_env, ev_env, require="TRUSTED_LOCAL", keys=None, **expect) -> dict:
    return {"bundle_version": 1,
            "trusted_keys": keys if keys is not None else [{"key_id": KID_A, "public_key_hex": RAW_A.hex()}],
            "certificate_envelope": cert_env, "evidence_envelope": ev_env,
            "expect": {"require_trust": require, **expect}}


def good(ev_over=None, cert_over=None, ev_version=2, cert_version=2, **kw):
    ev_f = evidence_fields(**(ev_over or {}))
    if ev_version == 1:
        for k in ("trust_level", "evaluator_id", "execution_environment"):
            ev_f.pop(k, None)
    ev = VEPObject.create("Evidence", ev_f, ev_version)
    ev_env = sign_obj(ev)
    cf = cert_fields(ev, ev_env, **(cert_over or {}))
    if cert_version == 1:
        cf.pop("trust_level", None)
        cf.pop("evaluator_id", None)
    cert = VEPObject.create("Certificate", cf, cert_version)
    return bundle(sign_obj(cert), ev_env, **kw), cert, ev, ev_env


VECTORS: list[dict] = []


def add(vid: str, op: str, note: str, expect: dict, **inp) -> None:
    VECTORS.append({"id": vid, "op": op, "note": note, **inp, "expect": expect})


def vb(vid: str, note: str, b: dict, valid: bool, code: str | None) -> None:
    add(vid, "verify_bundle", note, {"valid": valid, "code": code}, bundle=b)


# ------------------------------------------------------------ canonicalization
def canon(vid, note, text: bytes | str, out: str | None):
    data = text.encode() if isinstance(text, str) else text
    add(vid, "canonicalize", note, {"valid": False} if out is None else {"valid": True, "output_hex": out.encode().hex()},
        input_hex=data.hex())


canon("canon-001", "keys sorted, whitespace removed", '{ "b": 1,\n "a": [true, null, "x"] }', '{"a":[true,null,"x"],"b":1}')
canon("canon-002", "non-ASCII is emitted as raw UTF-8, not escaped", '{"k":"é€😀"}', '{"k":"é€😀"}')
canon("canon-003", "escapes: only quote, backslash and C0 controls; 0x7f and U+2028 stay raw",
      '"\\u0000\\u001f\\u007f\\u2028\\"\\\\\\/\\b\\f\\n\\r\\t"', '"\\u0000\\u001f\u007f \\"\\\\/\\b\\f\\n\\r\\t"')
canon("canon-004", "key order is by code point, not UTF-16 unit (U+FFFF before U+10000)",
      '{"\\ud800\\udc00":1,"\\uffff":2}', '{"￿":2,"\U00010000":1}')
canon("canon-005", "largest integer", "9223372036854775807", "9223372036854775807")
canon("canon-006", "integer minus zero is 0", "-0", "0")
canon("canon-007", "empty containers", '{"a":{},"b":[]}', '{"a":{},"b":[]}')
canon("canon-008", "escaped solidus and unicode escape are normalised", '"\\u0041\\/"', '"A/"')
canon("canon-009", "surrogate pair escape becomes raw astral character", '"\\ud83d\\ude00"', '"😀"')
canon("canon-010", "64 nested lists around a scalar is the deepest accepted", "[" * 64 + "1" + "]" * 64, "[" * 64 + "1" + "]" * 64)
canon("canon-011", "65 nested lists around a scalar exceeds the depth limit", "[" * 65 + "1" + "]" * 65, None)
canon("canon-012", "same keys in different order canonicalise equally (second of pair)", '{"a":1,"b":2}', '{"a":1,"b":2}')
canon("canon-013", "negative integer", "-9223372036854775807", "-9223372036854775807")
for n, (note, txt) in enumerate([
    ("duplicate key", '{"a":1,"a":2}'), ("float", "1.0"), ("exponent", "1e3"), ("NaN", "NaN"), ("Infinity", "Infinity"),
    ("minus Infinity", "-Infinity"), ("integer above 2^63-1", "9223372036854775808"),
    ("minimum int64 is out of range", "-9223372036854775808"), ("trailing comma", "[1,]"),
    ("leading zero", "01"), ("single quotes", "{'a':1}"), ("empty input", ""), ("trailing garbage", "{}x"),
    ("lone high surrogate escape", '"\\ud800"'), ("lone low surrogate escape", '"\\udc00"'),
    ("raw control character in string", '"a\tb"'), ("invalid escape", '"\\x41"'), ("bare word", "tru"),
    ("float in nested object", '{"a":[{"b":0.5}]}'), ("duplicate key in nested object", '{"a":{"b":1,"b":1}}'),
    ("unterminated string", '"abc'), ("whitespace only", "  "),
], start=1):
    canon(f"canon-bad-{n:03d}", f"reject: {note}", txt, None)
canon("canon-bad-101", "reject: UTF-8 BOM", b"\xef\xbb\xbf{}", None)
canon("canon-bad-102", "reject: invalid UTF-8 byte", b'"\xff"', None)
canon("canon-bad-103", "reject: overlong UTF-8", b'"\xc0\xaf"', None)
canon("canon-bad-104", "reject: UTF-8 encoded surrogate", b'"\xed\xa0\x80"', None)

# ------------------------------------------------------------ domain hash
for n, (dom, data) in enumerate([("vep.Test.v1", b""), ("vep.Test.v1", b"abc"), ("", b"x"), ("vep.é.v1", "é".encode()),
                                 ("vep.Test.v1", bytes(range(256)))], start=1):
    from vep.canonical import domain_hash
    add(f"hash-{n:03d}", "domain_hash", "length-prefixed domain separation", {"digest": domain_hash(dom, data)},
        domain=dom, data_hex=data.hex())
add("hash-006", "domain_hash", "different domain, same data, different digest",
    {"digest": domain_hash("vep.Other.v1", b"abc")}, domain="vep.Other.v1", data_hex=b"abc".hex())
assert VECTORS[-1]["expect"]["digest"] != VECTORS[-5]["expect"]["digest"]

# ------------------------------------------------------------ object identity
for n, (t, f) in enumerate([
    ("Objective", {"title": "t", "description": "", "base_snapshot_id": IDS["snap"], "policy_id": IDS["pol"],
                   "created_by": "op", "created_at": "2026-01-01T00:00:00Z"}),
    ("Snapshot", {"manifest_version": 1, "entries": [{"path": "a.py", "digest": h("a"), "executable": False}]}),
    ("Candidate", {"objective_id": IDS["obj"], "base_snapshot_id": IDS["snap"], "snapshot_id": IDS["snap"],
                   "author": "agent", "created_at": "2026-01-01T00:00:00Z"}),
    ("Observation", {"subject": "s", "metric": "m", "value": "1.5", "unit": "s", "source": "measured",
                     "observed_at": "2026-01-01T00:00:00Z"}),
    ("Evidence", evidence_fields()),
], start=1):
    sv = objects.version_of(t)
    o = VEPObject.create(t, f, sv)
    add(f"id-{n:03d}", "object_id", f"{t} v{sv} identity", {"canonical_hex": o.canonical_bytes().hex(), "id": o.id},
        type=t, schema_version=sv, fields=f)
o1 = VEPObject.create("Evidence", {k: v for k, v in evidence_fields().items() if k not in ("trust_level", "evaluator_id", "execution_environment")}, 1)
add("id-006", "object_id", "same type, schema v1: different domain gives different id",
    {"canonical_hex": o1.canonical_bytes().hex(), "id": o1.id}, type="Evidence", schema_version=1,
    fields=o1.fields)

# ------------------------------------------------------------ bundles: valid
b, cert, ev, ev_env = good()
vb("bundle-001", "valid TRUSTED_LOCAL v2", b, True, None)
vb("bundle-002", "valid with matching objective/policy/snapshot expectations",
   good(objective_id=IDS["obj"], policy_id=IDS["pol"], snapshot_id=IDS["snap"])[0], True, None)
iso_over = {"trust_level": "ISOLATED_VERIFIED", "isolation": "DOCKER_GVISOR", "isolation_attestation_digest": h("att"),
            "evaluator_id": "vep-local-evaluator/0.5.0/ISOLATED_VERIFIED"}
vb("bundle-003", "valid ISOLATED_VERIFIED requiring ISOLATED_VERIFIED",
   good(iso_over, {"trust_level": "ISOLATED_VERIFIED", "evaluator_id": iso_over["evaluator_id"]}, require="ISOLATED_VERIFIED")[0], True, None)
vb("bundle-004", "valid ISOLATED_VERIFIED satisfies a TRUSTED_LOCAL requirement",
   good(iso_over, {"trust_level": "ISOLATED_VERIFIED", "evaluator_id": iso_over["evaluator_id"]})[0], True, None)
vb("bundle-005", "valid legacy v1 evidence and certificate (trust derived from isolation, never upgraded)",
   good(ev_version=1, cert_version=1)[0], True, None)
vb("bundle-006", "valid extra trusted key present", good(keys=[{"key_id": KID_B, "public_key_hex": RAW_B.hex()},
   {"key_id": KID_A, "public_key_hex": RAW_A.hex()}])[0], True, None)

# ------------------------------------------------------------ bundles: trust and policy
vb("bundle-101", "TRUSTED_LOCAL evidence cannot satisfy ISOLATED_VERIFIED requirement", good(require="ISOLATED_VERIFIED")[0], False, "TRUST_INSUFFICIENT")
vb("bundle-102", "legacy v1 evidence claiming DOCKER_GVISOR is UNVERIFIED",
   good({"isolation": "DOCKER_GVISOR"}, ev_version=1, cert_version=1)[0], False, "TRUST_INSUFFICIENT")
vb("bundle-103", "policy mismatch", good(policy_id="pol-" + h("other"))[0], False, "POLICY_MISMATCH")
vb("bundle-104", "objective mismatch", good(objective_id="obj-" + h("other"))[0], False, "OBJECTIVE_MISMATCH")
vb("bundle-105", "snapshot mismatch (source changed since certification)", good(snapshot_id="snap-" + h("other"))[0], False, "SNAPSHOT_MISMATCH")
vb("bundle-106", "certificate trust level differs from its evidence",
   good(cert_over={"trust_level": "ISOLATED_VERIFIED"})[0], False, "TRUST_BINDING_MISMATCH")
vb("bundle-107", "certificate evaluator id differs from its evidence",
   good(cert_over={"evaluator_id": "other/1/TRUSTED_LOCAL"})[0], False, "TRUST_BINDING_MISMATCH")
unv = {"trust_level": "UNVERIFIED", "verdict": "FAIL", "exit_code": 1, "tests_passed": 2, "tests_failed": 1}
vb("bundle-108", "UNVERIFIED evidence never satisfies anything",
   good(unv, {"trust_level": "UNVERIFIED"})[0], False, "TRUST_INSUFFICIENT")

# ------------------------------------------------------------ bundles: evidence content
vb("bundle-201", "evidence verdict FAIL", good({"verdict": "FAIL", "exit_code": 1, "tests_failed": 1, "tests_passed": 2})[0], False, "EVIDENCE_NOT_PASSING")
vb("bundle-202", "zero tests passed", good({"tests_passed": 0, "tests_run": 3, "tests_skipped": 3})[0], False, "EVIDENCE_NOT_PASSING")
vb("bundle-203", "every test skipped", good({"tests_passed": 1, "tests_run": 3, "tests_skipped": 3})[0], False, "EVIDENCE_NOT_PASSING")
vb("bundle-204", "PASS verdict but failures listed", good({"tests_failed": 1})[0], False, "EVIDENCE_NOT_PASSING")
vb("bundle-205", "evidence executed a different tree than the certified snapshot",
   good({"staged_tree_snapshot_id": "snap-" + h("other")})[0], False, "EVIDENCE_SNAPSHOT_MISMATCH")
vb("bundle-206", "evidence policy differs from certificate policy", good({"policy_id": "pol-" + h("other")})[0], False, "BINDING_MISMATCH")
vb("bundle-207", "evidence candidate differs from certificate candidate", good({"candidate_id": "cand-" + h("other")})[0], False, "BINDING_MISMATCH")

# ------------------------------------------------------------ bundles: bindings
b0, cert0, ev0, ev_env0 = good()
other_ev = VEPObject.create("Evidence", evidence_fields(tests_run=4, tests_discovered=4, tests_passed=4), 2)
b = copy.deepcopy(b0)
b["evidence_envelope"] = sign_obj(other_ev)
vb("bundle-301", "evidence envelope swapped for another valid, signed evidence", b, False, "EVIDENCE_DIGEST_MISMATCH")
cert_wrong_id = VEPObject.create("Certificate", cert_fields(ev0, ev_env0, evidence_id=other_ev.id), 2)
vb("bundle-302", "certificate names a different evidence id than the digest-bound envelope",
   bundle(sign_obj(cert_wrong_id), ev_env0), False, "IDENTITY_MISMATCH")

# ------------------------------------------------------------ bundles: signatures and envelopes
def mutate(path, fn):
    b = copy.deepcopy(b0)
    fn(b)
    return b


flip = lambda s: base64.b64encode(bytes([base64.b64decode(s)[0] ^ 1]) + base64.b64decode(s)[1:]).decode()
vb("bundle-401", "certificate signature bit flipped", mutate(0, lambda b: b["certificate_envelope"]["signatures"][0].update(sig=flip(b["certificate_envelope"]["signatures"][0]["sig"]))), False, "SIGNATURE_INVALID")
vb("bundle-402", "evidence payload byte flipped after signing", mutate(0, lambda b: b["evidence_envelope"].update(payload=flip(b["evidence_envelope"]["payload"]))), False, "SIGNATURE_INVALID")
vb("bundle-403", "certificate payload byte flipped after signing", mutate(0, lambda b: b["certificate_envelope"].update(payload=flip(b["certificate_envelope"]["payload"]))), False, "SIGNATURE_INVALID")
vb("bundle-404", "signed by an untrusted key", bundle(sign_obj(cert0, k=KB, kid=KID_B), ev_env0), False, "UNTRUSTED_KEY")
vb("bundle-405", "key id claims A but signature made by B",
   bundle(sign_obj(cert0, k=KB, kid=KID_A), ev_env0), False, "SIGNATURE_INVALID")
vb("bundle-406", "trusted key entry whose id is not the hash of the key",
   good(keys=[{"key_id": KID_A, "public_key_hex": RAW_B.hex()}])[0], False, "MALFORMED_BUNDLE")
vb("bundle-407", "wrong payloadType", mutate(0, lambda b: b["certificate_envelope"].update(payloadType="text/plain")), False, "MALFORMED_ENVELOPE")
vb("bundle-408", "two signatures", mutate(0, lambda b: b["certificate_envelope"]["signatures"].append(b["certificate_envelope"]["signatures"][0])), False, "MALFORMED_ENVELOPE")
vb("bundle-409", "payload is not valid base64", mutate(0, lambda b: b["certificate_envelope"].update(payload="***")), False, "MALFORMED_ENVELOPE")
vb("bundle-410", "unexpected envelope field", mutate(0, lambda b: b["certificate_envelope"].update(extra=1)), False, "MALFORMED_ENVELOPE")
vb("bundle-411", "no signatures", mutate(0, lambda b: b["certificate_envelope"].update(signatures=[])), False, "MALFORMED_ENVELOPE")
vb("bundle-412", "signature field missing keyid", mutate(0, lambda b: b["certificate_envelope"]["signatures"][0].pop("keyid")), False, "MALFORMED_ENVELOPE")
vb("bundle-413", "base64 with newline is rejected", mutate(0, lambda b: b["certificate_envelope"].update(payload=b["certificate_envelope"]["payload"][:8] + "\n" + b["certificate_envelope"]["payload"][8:])), False, "MALFORMED_ENVELOPE")
vb("bundle-414", "envelope is not an object", mutate(0, lambda b: b.update(certificate_envelope=[])), False, "MALFORMED_ENVELOPE")

# ------------------------------------------------------------ bundles: signed but malformed payloads
cp = cert0.canonical_bytes()
vb("bundle-501", "validly signed but non-canonical payload (extra whitespace)",
   bundle(sign_payload(cp.replace(b'"fields":', b'"fields": ', 1)), ev_env0), False, "NONCANONICAL_PAYLOAD")
vb("bundle-502", "validly signed payload with duplicate key",
   bundle(sign_payload(cp[:-1] + b',"type":"Certificate"}'), ev_env0), False, "MALFORMED_PAYLOAD")
vb("bundle-503", "validly signed payload containing a float",
   bundle(sign_payload(cp.replace(b'"schema_version":2', b'"schema_version":2.0')), ev_env0), False, "MALFORMED_PAYLOAD")
vb("bundle-504", "validly signed payload that is not JSON", bundle(sign_payload(b"not json"), ev_env0), False, "MALFORMED_PAYLOAD")
vb("bundle-505", "unknown schema version 3",
   bundle(sign_payload(cp.replace(b'"schema_version":2', b'"schema_version":3')), ev_env0), False, "UNSUPPORTED_SCHEMA_VERSION")
vb("bundle-506", "schema version 0", bundle(sign_payload(cp.replace(b'"schema_version":2', b'"schema_version":0')), ev_env0), False, "UNSUPPORTED_SCHEMA_VERSION")
vb("bundle-507", "evidence presented where a certificate is required",
   bundle(sign_obj(ev0), ev_env0), False, "WRONG_TYPE")
vb("bundle-508", "certificate missing a required field",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {k: v for k, v in cert0.fields.items() if k != "issued_at"}})), ev_env0), False, "SCHEMA_INVALID")
vb("bundle-509", "certificate with an unknown field",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {**cert0.fields, "extra": "x"}})), ev_env0), False, "SCHEMA_INVALID")
vb("bundle-510", "certificate with malformed id",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {**cert0.fields, "candidate_id": "cand-xyz"}})), ev_env0), False, "SCHEMA_INVALID")
vb("bundle-511", "certificate with a bad timestamp",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {**cert0.fields, "issued_at": "yesterday"}})), ev_env0), False, "SCHEMA_INVALID")
vb("bundle-512", "certificate with an unknown trust level",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {**cert0.fields, "trust_level": "SUPER"}})), ev_env0), False, "SCHEMA_INVALID")
bad_ev_fields = {**ev0.fields, "isolation": "DOCKER_GVISOR"}  # TRUSTED_LOCAL claiming isolation
bad_ev_env = sign_payload(canonical_bytes({"type": "Evidence", "schema_version": 2, "fields": bad_ev_fields}))
vb("bundle-513", "evidence claims TRUSTED_LOCAL while recording gVisor isolation (cross-field rule)",
   bundle(sign_obj(VEPObject.create("Certificate", cert_fields(ev0, bad_ev_env), 2)), bad_ev_env), False, "SCHEMA_INVALID")
vb("bundle-514", "evidence with PASS verdict and UNVERIFIED trust (cross-field rule)",
   bundle(sign_obj(VEPObject.create("Certificate", cert_fields(ev0, ev_env0), 2)),
          sign_payload(canonical_bytes({"type": "Evidence", "schema_version": 2, "fields": {**ev0.fields, "trust_level": "UNVERIFIED"}}))),
   False, "SCHEMA_INVALID")
vb("bundle-515", "null for a required field",
   bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": {**cert0.fields, "issued_at": None}})), ev_env0), False, "SCHEMA_INVALID")
vb("bundle-516", "explicit null for an optional field is not canonical",
   bundle(sign_obj(VEPObject.create("Certificate", cert_fields(ev0, ev_env0), 2)),
          sign_payload(canonical_bytes({"type": "Evidence", "schema_version": 2, "fields": {**ev0.fields, "isolation_attestation_digest": None}}))),
   False, "NONCANONICAL_PAYLOAD")

# ------------------------------------------------------------ bundles: shape
vb("bundle-601", "unsupported bundle version", mutate(0, lambda b: b.update(bundle_version=2)), False, "UNSUPPORTED_BUNDLE_VERSION")
vb("bundle-602", "bundle version is not an integer", mutate(0, lambda b: b.update(bundle_version="1")), False, "MALFORMED_BUNDLE")
vb("bundle-603", "missing evidence envelope", mutate(0, lambda b: b.pop("evidence_envelope")), False, "MALFORMED_BUNDLE")
vb("bundle-604", "require_trust UNVERIFIED is not a valid requirement", mutate(0, lambda b: b["expect"].update(require_trust="UNVERIFIED")), False, "MALFORMED_BUNDLE")
vb("bundle-605", "unknown expectation field", mutate(0, lambda b: b["expect"].update(color="red")), False, "MALFORMED_BUNDLE")
vb("bundle-606", "bundle is not an object", [1, 2], False, "MALFORMED_BUNDLE")
vb("bundle-607", "no trusted keys", mutate(0, lambda b: b.update(trusted_keys=[])), False, "UNTRUSTED_KEY")
vb("bundle-608", "extra top-level field", mutate(0, lambda b: b.update(extra=True)), False, "MALFORMED_BUNDLE")

def sf(vid, note, **over):
    f = {**cert0.fields, **over}
    vb(vid, note, bundle(sign_payload(canonical_bytes({"type": "Certificate", "schema_version": 2, "fields": f})), ev_env0),
       False, "SCHEMA_INVALID")


sf("bundle-517", "id with a trailing newline is not an id", candidate_id=IDS["cand"] + "\n")
sf("bundle-518", "timestamp with a trailing newline", issued_at="2026-01-01T00:00:02Z\n")
sf("bundle-519", "timestamp with non-ASCII (Arabic-Indic) digits", issued_at="\u0662\u0660\u0662\u0666-01-01T00:00:02Z")
sf("bundle-520", "digest with a trailing newline", evidence_envelope_digest=cert0["evidence_envelope_digest"] + "\n")
sf("bundle-521", "digest in upper case", evidence_envelope_digest=cert0["evidence_envelope_digest"].upper())
sf("bundle-522", "id with unknown prefix", snapshot_id="zzz-" + h("snap"))
sf("bundle-523", "id with the wrong type prefix", snapshot_id="obj-" + h("snap"))

SUITE = {"suite": "vep-conformance", "suite_version": conformance.SUITE_VERSION, "canonical_format": "VEP-C1",
         "protocol_version": "0.3", "bundle_version": conformance.BUNDLE_VERSION,
         "reason_codes": list(conformance.CODES), "vectors": VECTORS}


def main() -> int:
    for v in VECTORS:  # the reference must agree with the intent written above
        got = conformance.run_vector(v)
        if not conformance.check_vector(v, got):
            print(f"INTENT MISMATCH {v['id']} ({v['note']}): expected {v['expect']} got {got}", file=sys.stderr)
            return 2
    text = json.dumps(SUITE, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("conformance suite is stale or missing", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(VECTORS)} vectors, sha256 {hashlib.sha256(text.encode()).hexdigest()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
