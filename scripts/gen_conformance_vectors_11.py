"""Generate conformance/vectors/suite-1.1.json: the frozen 1.0 vectors, unchanged, plus authorized-verification vectors (trust policies).

    python scripts/gen_conformance_vectors_11.py            writes the file
    python scripts/gen_conformance_vectors_11.py --check    exit 1 if the committed file differs

suite-1.0.json is never modified. Expected results are asserted against the stated intent before anything is written.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("gen10", ROOT / "scripts" / "gen_conformance_vectors.py")
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
from vep import conformance, trustpolicy  # noqa: E402
from vep.objects import VEPObject  # noqa: E402

OUT = ROOT / "conformance" / "vectors" / "suite-1.1.json"
NOW = "2026-06-01T00:00:00Z"
IDS = g.IDS
V: list[dict] = []


def pol(issuers=None, evaluators=("vep-local-evaluator/*",), require="TRUSTED_LOCAL", snapshot=None, objective=None, policy=None,
        ev_versions=(2,), cert_versions=(2,), legacy=False, name="relying-party"):
    return trustpolicy.make_policy(name, issuers if issuers is not None else [trustpolicy.issuer(g.RAW_A)], list(evaluators), require,
                                   snapshot_id=snapshot or IDS["snap"], objective_id=objective, policy_id=policy, evidence_versions=ev_versions,
                                   certificate_versions=cert_versions, allow_legacy_evidence=legacy)


def v2(b1):
    return {"bundle_version": 2, "certificate_envelope": b1["certificate_envelope"], "evidence_envelope": b1["evidence_envelope"]}


def add(vid, note, bundle, policy, valid, code, now=NOW):
    V.append({"id": vid, "op": "verify_authorized", "note": note, "bundle": bundle, "trust_policy": policy, "now": now, "expect": {"valid": valid, "code": code}})


base, cert0, ev0, ev_env0 = g.good()
B = v2(base)
add("auth-001", "valid: issuer, evaluator (prefix rule), trust level and snapshot all authorized by the policy", B, pol(), True, None)
add("auth-002", "valid with objective and policy expectations", B, pol(objective=IDS["obj"], policy=IDS["pol"]), True, None)
add("auth-003", "valid: evaluator authorized by exact string", B, pol(evaluators=("vep-local-evaluator/0.5.0/TRUSTED_LOCAL",)), True, None)
iso_over = {"trust_level": "ISOLATED_VERIFIED", "isolation": "DOCKER_GVISOR", "isolation_attestation_digest": g.h("att"), "evaluator_id": "vep-local-evaluator/0.5.0/ISOLATED_VERIFIED"}
isob = v2(g.good(iso_over, {"trust_level": "ISOLATED_VERIFIED", "evaluator_id": iso_over["evaluator_id"]})[0])
add("auth-004", "valid: ISOLATED_VERIFIED required and present", isob, pol(require="ISOLATED_VERIFIED"), True, None)
legacy = v2(g.good(ev_version=1, cert_version=1)[0])
add("auth-005", "valid: legacy v1 pair when the policy explicitly permits legacy evidence and versions 1", legacy, pol(ev_versions=(1, 2), cert_versions=(1, 2), legacy=True), True, None)
add("auth-006", "valid: retired key still accepted for a certificate issued before its retirement (rotation)", B,
    pol([trustpolicy.issuer(g.RAW_A, status="retired", status_effective_at="2026-02-01T00:00:00Z"), trustpolicy.issuer(g.RAW_B, valid_from="2026-02-01T00:00:00Z")]), True, None)

# the attacker: self-consistent, signed by a key the relying party never authorized
bk_ev = VEPObject.create("Evidence", g.evidence_fields(), 2)
bk_ev_env = g.sign_obj(bk_ev, k=g.KB, kid=g.KID_B)
bk_cert = VEPObject.create("Certificate", g.cert_fields(bk_ev, bk_ev_env, issuer_key_id=g.KID_B), 2)
attacker = {"bundle_version": 2, "certificate_envelope": g.sign_obj(bk_cert, k=g.KB, kid=g.KID_B), "evidence_envelope": bk_ev_env}
add("auth-101", "self-consistent bundle signed by an unauthorized key", attacker, pol(), False, "UNAUTHORIZED_ISSUER")
atk_eval = g.good({"evaluator_id": "attacker/1/TRUSTED_LOCAL"}, {"evaluator_id": "attacker/1/TRUSTED_LOCAL"})[0]
add("auth-102", "authorized key but an evaluator identity the policy does not authorize", v2(atk_eval), pol(), False, "EVALUATOR_NOT_AUTHORIZED")
add("auth-103", "compromised key: rejected for every certificate regardless of its dates", B, pol([trustpolicy.issuer(g.RAW_A, status="compromised", status_effective_at="2026-05-01T00:00:00Z")]), False, "REVOKED_KEY")
add("auth-104", "retired key: certificate issued at or after retirement", B, pol([trustpolicy.issuer(g.RAW_A, status="retired", status_effective_at="2026-01-01T00:00:02Z")]), False, "REVOKED_KEY")
add("auth-105", "key not yet valid at issuance", B, pol([trustpolicy.issuer(g.RAW_A, valid_from="2026-03-01T00:00:00Z")]), False, "KEY_NOT_YET_VALID")
add("auth-106", "key expired before issuance", B, pol([trustpolicy.issuer(g.RAW_A, valid_until="2026-01-01T00:00:02Z")]), False, "KEY_EXPIRED")
add("auth-107", "certificate dated after the relying party's clock", B, pol(), False, "ISSUED_IN_FUTURE", now="2025-12-31T00:00:00Z")
mism = VEPObject.create("Certificate", g.cert_fields(ev0, ev_env0, issuer_key_id=g.KID_B), 2)
add("auth-108", "certificate names a different issuer than the key that signed it", {"bundle_version": 2, "certificate_envelope": g.sign_obj(mism), "evidence_envelope": ev_env0},
    pol([trustpolicy.issuer(g.RAW_A), trustpolicy.issuer(g.RAW_B)]), False, "ISSUER_KEY_MISMATCH")
evB = {"bundle_version": 2, "certificate_envelope": base["certificate_envelope"], "evidence_envelope": g.sign_obj(ev0, k=g.KB, kid=g.KID_B)}
evB_cert = VEPObject.create("Certificate", g.cert_fields(ev0, evB["evidence_envelope"]), 2)
evB["certificate_envelope"] = g.sign_obj(evB_cert)
add("auth-109", "evidence signed by an unauthorized key while the certificate is authorized", evB, pol(), False, "UNAUTHORIZED_ISSUER")
add("auth-110", "evidence schema version not permitted by the policy", B, pol(ev_versions=(1,)), False, "EVIDENCE_VERSION_NOT_PERMITTED")
add("auth-111", "certificate schema version not permitted by the policy", B, pol(cert_versions=(1,)), False, "CERTIFICATE_VERSION_NOT_PERMITTED")
add("auth-112", "legacy v1 evidence without explicit permission", legacy, pol(ev_versions=(1, 2), cert_versions=(1, 2), legacy=False), False, "LEGACY_EVIDENCE_NOT_PERMITTED")
add("auth-113", "TRUSTED_LOCAL evidence cannot satisfy a policy requiring ISOLATED_VERIFIED", B, pol(require="ISOLATED_VERIFIED"), False, "TRUST_INSUFFICIENT")
add("auth-114", "expected snapshot differs (source changed or wrong subject)", B, pol(snapshot="snap-" + g.h("other")), False, "SNAPSHOT_MISMATCH")
add("auth-115", "expected objective differs", B, pol(objective="obj-" + g.h("other")), False, "OBJECTIVE_MISMATCH")
add("auth-116", "expected acceptance policy differs", B, pol(policy="pol-" + g.h("other")), False, "POLICY_MISMATCH")
nosubj = pol(); nosubj["expect"] = {}
add("auth-117", "policy names no expected snapshot: the verifier refuses to emit an authorized result", B, nosubj, False, "SUBJECT_UNSPECIFIED")
for n, (note, mut) in enumerate([("unknown policy field", lambda p: p.update(extra=1)), ("issuer key id is not the hash of the key", lambda p: p["issuers"][0].update(key_id=g.KID_B)),
                                 ("require_trust UNVERIFIED", lambda p: p.update(require_trust="UNVERIFIED")),
                                 ("retired issuer without an effective date", lambda p: p["issuers"][0].update(status="retired")),
                                 ("duplicate issuer", lambda p: p["issuers"].append(copy.deepcopy(p["issuers"][0]))),
                                 ("unsupported trust policy version", lambda p: p.update(trust_policy_version=2)),
                                 ("no authorized evaluators", lambda p: p.update(authorized_evaluators=[]))], start=1):
    p = pol(); mut(p)
    add(f"auth-12{n}", f"malformed trust policy: {note}", B, p, False, "MALFORMED_TRUST_POLICY")
add("auth-130", "a v1 bundle (embedded keys and expectations) is not accepted by authorized verification", base, pol(), False, "UNSUPPORTED_BUNDLE_VERSION")
smug = copy.deepcopy(B); smug["trusted_keys"] = base["trusted_keys"]
add("auth-131", "a format-2 bundle cannot carry its own keys", smug, pol(), False, "MALFORMED_BUNDLE")
# cross-checks still apply
b = copy.deepcopy(B); b["evidence_envelope"] = g.sign_obj(VEPObject.create("Evidence", g.evidence_fields(tests_run=4, tests_discovered=4, tests_passed=4), 2))
add("auth-140", "evidence envelope replaced by another signed by the same authorized key", b, pol(), False, "EVIDENCE_DIGEST_MISMATCH")
fb, fcert, fev, fenv = g.good({"verdict": "FAIL", "exit_code": 1, "tests_failed": 1, "tests_passed": 2})
add("auth-141", "authorized issuer, but the evidence is a failing run", v2(fb), pol(), False, "EVIDENCE_NOT_PASSING")
b = copy.deepcopy(B); sig = b["certificate_envelope"]["signatures"][0]["sig"]; b["certificate_envelope"]["signatures"][0]["sig"] = g.flip(sig) if hasattr(g, "flip") else sig[::-1]
add("auth-142", "certificate signature corrupted", b, pol(), False, "SIGNATURE_INVALID")
bb = v2(g.good({"policy_id": "pol-" + g.h("o2")})[0])
add("auth-143", "evidence and certificate bind different acceptance policies", bb, pol(), False, "BINDING_MISMATCH")
other_ev = VEPObject.create("Evidence", g.evidence_fields(tests_run=4, tests_discovered=4, tests_passed=4), 2)
idm = VEPObject.create("Certificate", g.cert_fields(ev0, ev_env0, evidence_id=other_ev.id), 2)
add("auth-144", "certificate names a different evidence id than the digest-bound envelope", {"bundle_version": 2, "certificate_envelope": g.sign_obj(idm), "evidence_envelope": ev_env0}, pol(), False, "IDENTITY_MISMATCH")
add("auth-145", "certificate trust level differs from its evidence", v2(g.good(cert_over={"trust_level": "ISOLATED_VERIFIED"})[0]), pol(), False, "TRUST_BINDING_MISMATCH")
add("auth-146", "evidence executed a different tree than the certified snapshot", v2(g.good({"staged_tree_snapshot_id": "snap-" + g.h("other")})[0]), pol(), False, "EVIDENCE_SNAPSHOT_MISMATCH")
# policy identity vectors
for n, p in enumerate([pol(), pol([trustpolicy.issuer(g.RAW_A, status="retired", status_effective_at="2026-02-01T00:00:00Z"), trustpolicy.issuer(g.RAW_B)], require="ISOLATED_VERIFIED", objective=IDS["obj"])], start=1):
    V.append({"id": f"tpid-00{n}", "op": "trust_policy_id", "note": "content identity of a trust policy", "trust_policy": p, "expect": {"id": trustpolicy.policy_id(p)}})

old = json.loads((ROOT / "conformance" / "vectors" / "suite-1.0.json").read_text())
SUITE = {"suite": "vep-conformance", "suite_version": "1.1", "canonical_format": "VEP-C1", "protocol_version": "0.3", "bundle_versions": [1, 2],
         "extends": "1.0 (its 119 vectors are carried over verbatim)", "reason_codes": old["reason_codes"], "authorized_reason_codes": list(trustpolicy.AUTHORIZED_CODES),
         "vectors": old["vectors"] + V}


def main() -> int:
    for v in V:
        got = conformance.run_vector(v)
        if not conformance.check_vector(v, got):
            print(f"INTENT MISMATCH {v['id']} ({v['note']}): expected {v['expect']} got {got}", file=sys.stderr)
            return 2
    text = json.dumps(SUITE, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        return 0 if OUT.exists() and OUT.read_text() == text else 1
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(SUITE['vectors'])} vectors: {len(old['vectors'])} carried over + {len(V)} new)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
