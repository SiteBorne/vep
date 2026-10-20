"""Generate conformance/vectors/suite-1.2.json: the 1.1 vectors verbatim plus derived-evidence (exact-input reuse) vectors.

    python scripts/gen_conformance_vectors_12.py            writes the file
    python scripts/gen_conformance_vectors_12.py --check    exit 1 if the committed file differs

suite-1.0.json and suite-1.1.json are never modified. Expected results are asserted against the stated intent before anything is written.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
spec = importlib.util.spec_from_file_location("gen11", ROOT / "scripts" / "gen_conformance_vectors_11.py")
g11 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g11)
g, pol, IDS, NOW = g11.g, g11.pol, g11.IDS, g11.NOW
from vep import conformance, trustpolicy  # noqa: E402
from vep.canonical import canonical_bytes, sha256_hex  # noqa: E402
from vep.objects import VEPObject  # noqa: E402

OUT = ROOT / "conformance" / "vectors" / "suite-1.2.json"
C2, O2 = "cand-" + g.h("cand2"), "obj-" + g.h("obj2")
V: list[dict] = []


def att_fields(ev: VEPObject, ev_env: dict, **over) -> dict:
    f = {"candidate_id": C2, "objective_id": O2, "snapshot_id": ev["snapshot_id"], "policy_id": ev["policy_id"], "original_evidence_id": ev.id,
         "original_evidence_envelope_digest": sha256_hex(canonical_bytes(ev_env)), "original_candidate_id": ev["candidate_id"],
         "original_objective_id": ev["objective_id"], "reuse_mode": "EXACT_INPUT", "trust_level": "TRUSTED_LOCAL",
         "evaluator_id": ev.get("evaluator_id", "legacy"), "runner_digest": ev["runner_digest"],
         "environment_digest": sha256_hex(canonical_bytes(ev.get("execution_environment", {}))), "issuer_key_id": g.KID_A, "issued_at": "2026-01-02T00:00:00Z"}
    f.update(over)
    return f


def bundle3(ev: VEPObject, ev_env: dict, att_over=None, **sign) -> dict:
    return {"bundle_version": 3, "attestation_envelope": g.sign_obj(VEPObject.create("DerivedAttestation", att_fields(ev, ev_env, **(att_over or {})), 1), **sign),
            "evidence_envelope": ev_env}


def add(vid, note, bundle, policy, valid, code, now=NOW):
    V.append({"id": vid, "op": "verify_derived", "note": note, "bundle": bundle, "trust_policy": policy, "now": now, "expect": {"valid": valid, "code": code}})


_, _, ev0, env0 = g.good()
B = bundle3(ev0, env0)
add("der-001", "valid: attestation and the original evidence signed by an authorized issuer, exact bindings", B, pol(), True, None)
add("der-002", "valid with objective and policy expectations on the DERIVED candidate's objective", B, pol(objective=O2, policy=IDS["pol"]), True, None)
add("der-003", "valid: attestation issued before the retirement of a rotated key", B, pol([trustpolicy.issuer(g.RAW_A, status="retired", status_effective_at="2026-02-01T00:00:00Z"), trustpolicy.issuer(g.RAW_B, valid_from="2026-02-01T00:00:00Z")]), True, None)
# transport / structure
add("der-101", "a certificate bundle (format 2) is not a derived bundle", g11.v2(g.good()[0]), pol(), False, "UNSUPPORTED_BUNDLE_VERSION")
b = copy.deepcopy(B); b["extra"] = 1
add("der-102", "unexpected member in the bundle", b, pol(), False, "MALFORMED_BUNDLE")
wt = {"bundle_version": 3, "attestation_envelope": g.sign_obj(VEPObject.create("Certificate", g.cert_fields(ev0, env0), 2)), "evidence_envelope": env0}
add("der-103", "the attestation slot holds a certificate", wt, pol(), False, "WRONG_TYPE")
# authorization of signers
add("der-110", "attestation signed by a key the relying party never authorized", bundle3(ev0, env0, att_over={"issuer_key_id": g.KID_B}, k=g.KB, kid=g.KID_B), pol(), False, "UNAUTHORIZED_ISSUER")
b = copy.deepcopy(B); b["evidence_envelope"] = g.sign_obj(ev0, k=g.KB, kid=g.KID_B)
add("der-111", "original evidence signed by an unauthorized key", bundle3(ev0, b["evidence_envelope"]), pol(), False, "UNAUTHORIZED_ISSUER")
add("der-112", "attestation names a different issuer than the key that signed it", bundle3(ev0, env0, att_over={"issuer_key_id": g.KID_B}), pol([trustpolicy.issuer(g.RAW_A), trustpolicy.issuer(g.RAW_B)]), False, "ISSUER_KEY_MISMATCH")
add("der-113", "compromised key", B, pol([trustpolicy.issuer(g.RAW_A, status="compromised", status_effective_at="2026-05-01T00:00:00Z")]), False, "REVOKED_KEY")
add("der-114", "key not yet valid at the attestation time", B, pol([trustpolicy.issuer(g.RAW_A, valid_from="2026-03-01T00:00:00Z")]), False, "KEY_NOT_YET_VALID")
add("der-115", "key expired before the attestation time", B, pol([trustpolicy.issuer(g.RAW_A, valid_until="2026-01-02T00:00:00Z")]), False, "KEY_EXPIRED")
add("der-116", "attestation dated after the relying party's clock", B, pol(), False, "ISSUED_IN_FUTURE", now="2026-01-01T12:00:00Z")
add("der-117", "evidence schema version not permitted", B, pol(ev_versions=(1,)), False, "EVIDENCE_VERSION_NOT_PERMITTED")
b = copy.deepcopy(B); s = b["attestation_envelope"]["signatures"][0]["sig"]; b["attestation_envelope"]["signatures"][0]["sig"] = g.flip(s)
add("der-118", "attestation signature corrupted", b, pol(), False, "SIGNATURE_INVALID")
# derivation chain
add("der-120", "attestation digest does not match the supplied evidence envelope", bundle3(ev0, env0, att_over={"original_evidence_envelope_digest": g.h("other")}), pol(), False, "EVIDENCE_DIGEST_MISMATCH")
add("der-121", "attestation names a different evidence id than the digest-bound envelope", bundle3(ev0, env0, att_over={"original_evidence_id": "evd-" + g.h("else")}), pol(), False, "IDENTITY_MISMATCH")
legacy_ev, legacy_env = g.good(ev_version=1, cert_version=1)[2:4]
add("der-122", "legacy v1 evidence can never be reused", bundle3(legacy_ev, legacy_env, att_over={"evaluator_id": "x"}), pol(ev_versions=(1, 2), legacy=True), False, "LEGACY_EVIDENCE_NOT_REUSABLE")
add("der-123", "claimed original candidate is not the evidence's candidate", bundle3(ev0, env0, att_over={"original_candidate_id": "cand-" + g.h("liar")}), pol(), False, "DERIVATION_ORIGIN_MISMATCH")
add("der-124", "claimed original objective is not the evidence's objective", bundle3(ev0, env0, att_over={"original_objective_id": "obj-" + g.h("liar")}), pol(), False, "DERIVATION_ORIGIN_MISMATCH")
add("der-125", "attestation for the evidence's own candidate is not a derivation", bundle3(ev0, env0, att_over={"candidate_id": ev0["candidate_id"]}), pol(), False, "NOT_DERIVED")
add("der-126", "attested policy differs from the evidence's policy", bundle3(ev0, env0, att_over={"policy_id": "pol-" + g.h("p2")}), pol(), False, "BINDING_MISMATCH")
add("der-127", "attested snapshot differs from the evidence's snapshot", bundle3(ev0, env0, att_over={"snapshot_id": "snap-" + g.h("s2")}), pol(snapshot="snap-" + g.h("s2")), False, "BINDING_MISMATCH")
st_ev = VEPObject.create("Evidence", g.evidence_fields(staged_tree_snapshot_id="snap-" + g.h("staged")), 2)
add("der-128", "evidence executed a different tree than the attested snapshot", bundle3(st_ev, g.sign_obj(st_ev)), pol(), False, "EVIDENCE_SNAPSHOT_MISMATCH")
add("der-129", "attested trust level differs from the evidence's", bundle3(ev0, env0, att_over={"trust_level": "ISOLATED_VERIFIED"}), pol(), False, "TRUST_BINDING_MISMATCH")
add("der-130", "attested evaluator differs from the evidence's", bundle3(ev0, env0, att_over={"evaluator_id": "other/1/TRUSTED_LOCAL"}), pol(), False, "TRUST_BINDING_MISMATCH")
add("der-131", "attested runner differs from the evidence's (toolchain binding)", bundle3(ev0, env0, att_over={"runner_digest": g.h("other-runner")}), pol(), False, "RUNNER_BINDING_MISMATCH")
add("der-132", "attested environment differs from the evidence's (toolchain binding)", bundle3(ev0, env0, att_over={"environment_digest": g.h("other-env")}), pol(), False, "ENVIRONMENT_BINDING_MISMATCH")
fail_ev = VEPObject.create("Evidence", g.evidence_fields(verdict="FAIL", exit_code=1, tests_failed=1, tests_passed=2), 2)
add("der-133", "the original evidence is a failing run", bundle3(fail_ev, g.sign_obj(fail_ev)), pol(), False, "EVIDENCE_NOT_PASSING")
# relying-party policy
add("der-140", "evaluator not authorized by the policy", B, pol(evaluators=("someone-else/*",)), False, "EVALUATOR_NOT_AUTHORIZED")
add("der-141", "policy requires isolated evidence", B, pol(require="ISOLATED_VERIFIED"), False, "TRUST_INSUFFICIENT")
add("der-142", "expected objective differs from the derived candidate's", B, pol(objective=IDS["obj"]), False, "OBJECTIVE_MISMATCH")
add("der-143", "expected policy differs", B, pol(policy="pol-" + g.h("zz")), False, "POLICY_MISMATCH")
add("der-144", "expected snapshot differs", B, pol(snapshot="snap-" + g.h("zz")), False, "SNAPSHOT_MISMATCH")

old = json.loads((ROOT / "conformance" / "vectors" / "suite-1.1.json").read_text())
CODES = ["UNSUPPORTED_BUNDLE_VERSION", "MALFORMED_BUNDLE", "WRONG_TYPE", "UNAUTHORIZED_ISSUER", "ISSUER_KEY_MISMATCH", "REVOKED_KEY", "KEY_NOT_YET_VALID", "KEY_EXPIRED",
         "ISSUED_IN_FUTURE", "EVIDENCE_VERSION_NOT_PERMITTED", "SIGNATURE_INVALID", "EVIDENCE_DIGEST_MISMATCH", "IDENTITY_MISMATCH", "LEGACY_EVIDENCE_NOT_REUSABLE",
         "DERIVATION_ORIGIN_MISMATCH", "NOT_DERIVED", "BINDING_MISMATCH", "EVIDENCE_SNAPSHOT_MISMATCH", "TRUST_BINDING_MISMATCH", "RUNNER_BINDING_MISMATCH",
         "ENVIRONMENT_BINDING_MISMATCH", "EVIDENCE_NOT_PASSING", "EVALUATOR_NOT_AUTHORIZED", "TRUST_INSUFFICIENT", "OBJECTIVE_MISMATCH", "POLICY_MISMATCH", "SNAPSHOT_MISMATCH"]
SUITE = {**{k: v for k, v in old.items() if k not in ("vectors", "suite_version", "extends", "bundle_versions")}, "suite_version": "1.2", "bundle_versions": [1, 2, 3],
         "extends": "1.1 (its vectors are carried over verbatim)", "derived_reason_codes": CODES, "vectors": old["vectors"] + V}


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
