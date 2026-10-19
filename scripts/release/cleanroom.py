"""Clean-room usability test against an INSTALLED vep (no checkout, no editable install, no env help).

    python scripts/release/cleanroom.py --venv /path/to/venv

Prints a JSON list of the 17 required checks with PASS/FAIL; exit 0 only if all PASS.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CALC = "def add(a, b):\n    return a + b\n"
TESTS = ("import unittest\nfrom calc import add\n\nclass T(unittest.TestCase):\n"
         "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n    def test_neg(self):\n"
         "        self.assertEqual(add(-1, 1), 0)\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--venv", required=True)
    a = ap.parse_args()
    venv = Path(a.venv)
    vep, py = str(venv / "bin" / "vep"), str(venv / "bin" / "python")
    work = Path(tempfile.mkdtemp(prefix="vep-cleanroom-"))
    env = {"PATH": f"{venv / 'bin'}:/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8"}
    proj = work / "proj"; (proj / "tests").mkdir(parents=True)
    (proj / "calc.py").write_text(CALC); (proj / "tests" / "test_calc.py").write_text(TESTS)
    results: list[dict] = []

    def cli(*args, cwd=proj, ok=(0,)):
        r = subprocess.run([vep, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=600)
        return r

    def check(n, name, cond, detail=""):
        results.append({"n": n, "check": name, "status": "PASS" if cond else "FAIL", "detail": str(detail)[:300]})

    try:
        r = cli("--help", cwd=work); check(1, "vep --help works", r.returncode == 0 and "usage" in r.stdout.lower())
        r = cli("init", "--json"); check(2, "vep init works", r.returncode == 0 and len(json.loads(r.stdout)["signing_key_id"]) == 64, r.stderr)
        snap = cli("snapshot", "--json"); sid = json.loads(snap.stdout)["snapshot_id"] if snap.returncode == 0 else None
        check(3, "source snapshot can be created", bool(sid) and sid.startswith("snap-"), snap.stderr)
        r = cli("objective", "create", "--title", "cleanroom", "--budget", "1.00", "--json")
        obj = json.loads(r.stdout)["objective_id"] if r.returncode == 0 else None
        check(4, "objective can be registered", bool(obj), r.stderr)
        (proj / "calc.py").write_text(CALC + "\ndef sub(a, b):\n    return a - b\n")
        r = cli("candidate", "create", "--objective", obj, "--author", "cleanroom", "--json")
        cand = json.loads(r.stdout)["candidate_id"] if r.returncode == 0 else None
        check(5, "candidate can be created", bool(cand), r.stderr)
        r = cli("evaluate", "--candidate", cand, "--json")
        check(6, "trusted-local evaluation is denied without authorization", r.returncode == 7 and "Authorization" in r.stderr, (r.returncode, r.stderr))
        r = cli("evaluate", "--candidate", cand, "--trusted-local-execution", "--json")
        ev = json.loads(r.stdout) if r.returncode == 0 else {}
        check(7, "authorized local evaluation of trusted fixture code works",
              ev.get("verdict") == "PASS" and ev.get("trust_level") == "TRUSTED_LOCAL", r.stderr)
        check(8, "evidence generated and labeled TRUSTED_LOCAL", bool(ev.get("evidence_id")) and "no security isolation" in ev.get("isolation", ""))
        cert_id = None
        r = cli("certify", "--candidate", cand, "--json")
        if r.returncode == 0:
            cert_id = json.loads(r.stdout)["certificate_id"]
        v = cli("verify", "--certificate", cert_id or "cert-x", "--json")
        vj = json.loads(v.stdout) if v.returncode == 0 else {}
        check(9, "certificate can be verified (exact current source)", vj.get("mode") == "current-source" and vj.get("trust_level") == "TRUSTED_LOCAL", v.stderr)
        # 16 first (does not alter source): isolation cannot be represented as verified
        r1 = cli("evaluate", "--candidate", cand, "--isolated", "--json")
        r2 = cli("isolation", "verify", "--image", "python@sha256:" + "a" * 64, "--json")
        r3 = cli("verify", "--certificate", cert_id or "cert-x", "--require-trust", "ISOLATED_VERIFIED")
        att = json.loads(r2.stdout) if r2.stdout.strip().startswith("{") else {}
        check(16, "missing isolation cannot be represented as verified",
              r1.returncode == 8 and r2.returncode == 8 and att.get("status") == "ISOLATION_UNVERIFIED"
              and "PASS" not in {x["status"] for x in att.get("results", {}).values()} and r3.returncode == 4,
              (r1.returncode, r2.returncode, r3.returncode))
        # 11 tampered evidence rejected: corrupt the signed evidence envelope in the CAS
        import sqlite3
        con = sqlite3.connect(proj / ".vep" / "vep.db")
        d = con.execute("SELECT envelope_digest FROM evidence").fetchone()[0]; con.close()
        p = proj / ".vep" / "cas" / "objects" / d[:2] / d[2:]
        orig = p.read_bytes(); os.chmod(p, 0o644)
        p.write_bytes(orig[:-3] + b"xyz")
        r = cli("verify", "--certificate", cert_id, "--historical")
        check(11, "tampered evidence is rejected", r.returncode == 4, (r.returncode, r.stderr[:120]))
        p.write_bytes(orig)
        r = cli("verify", "--certificate", cert_id, "--historical")
        check(11.5, "restored evidence verifies again (the rejection was due to tampering)", r.returncode == 0, r.stderr)
        # 10 changing source invalidates current-state verification
        (proj / "calc.py").write_text(CALC + "\n# changed\n")
        r = cli("verify", "--certificate", cert_id)
        check(10, "changing the source invalidates current-state verification", r.returncode == 4 and "SOURCE_CHANGED" in r.stderr, r.stderr[:160])
        # 12 budget and tokens
        r = cli("budget", "create", "--account", "demo", "--kind", "objective", "--limit", "1", "--json")
        r2 = cli("budget", "reserve", "--account", "demo", "--amount", "0.4", "--key", "k1", "--json")
        r3 = cli("budget", "settle", "--key", "k1", "--amount", "0.3", "--json")
        r4 = cli("budget", "settle", "--key", "k1", "--amount", "0.31", "--json")  # conflicting
        usage = work / "usage.json"
        usage.write_text(json.dumps({"provider": "local", "model": "m", "pricing_version": "v1", "ordinary_input_tokens": 1000,
            "cached_input_tokens": 0, "cache_write_tokens": 0, "output_tokens": 500, "reasoning_tokens_in_output": 100,
            "usage_source": "simulated", "prices_per_million": {"input": "3", "cached_input": "0.3", "cache_write": "3.75", "output": "15"}}))
        r5 = cli("tokens", "record", "--candidate", cand, "--usage-file", str(usage), "--key", "r1", "--json")
        check(12, "budget and token operations work (conflicting settlement rejected)",
              (r.returncode, r2.returncode, r3.returncode, r4.returncode, r5.returncode) == (0, 0, 0, 5, 0)
              and json.loads(r5.stdout)["cost_usd"] == "0.0105", [x.returncode for x in (r, r2, r3, r4, r5)])
        mf, tf = work / "models.json", work / "task.json"
        mf.write_text(json.dumps([{"name": "x", "price_in_per_m": "1", "price_out_per_m": "2", "context_capacity": 100000,
            "capabilities": ["code"], "acceptance_estimate": "0.9", "success_lower_bound": "0.95", "latency_s": "3",
            "max_risk": "high", "evidence_source": "supplied"}]))
        tf.write_text(json.dumps({"input_tokens": 100, "output_tokens": 100, "required_capabilities": ["code"], "allowed_sources": ["supplied"]}))
        r = cli("route", "--models-file", str(mf), "--task-file", str(tf), "--json")
        check(13, "model routing works offline", r.returncode == 0 and json.loads(r.stdout)["decision"] == "SELECTED", r.stderr)
        r = cli("cache", "--prefix-tokens", "10000", "--input-price", "3", "--write-multiplier", "1.25", "--read-multiplier", "0.1", "--reuses", "5", "--json")
        check(14, "cache economics works offline", r.returncode == 0 and json.loads(r.stdout)["recommendation"] == "USE_CACHE", r.stderr)
        s1 = cli("simulate", "--tasks", "300", "--seed", "11", "--json"); s2 = cli("simulate", "--tasks", "300", "--seed", "11", "--json")
        check(15, "simulations are reproducible", s1.returncode == 0 and s1.stdout == s2.stdout and "SIMULATED" in s1.stdout)
        where = subprocess.run([py, "-c", "import vep,sys;print(vep.__file__)"], cwd=work, env=env, capture_output=True, text=True).stdout.strip()
        check(17, "installed package uses no developer-local files", "site-packages" in where and ".git" not in where
              and "/src/vep" not in where.replace("site-packages", ""), where)
    except Exception as exc:  # a crash is a failure, never a pass
        results.append({"n": -1, "check": "cleanroom crashed", "status": "FAIL", "detail": repr(exc)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ok = all(r["status"] == "PASS" for r in results) and len({int(r["n"]) for r in results}) >= 17
    print(json.dumps({"status": "PASS" if ok else "FAIL", "checks": sorted(results, key=lambda r: r["n"])}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
