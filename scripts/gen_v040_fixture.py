"""Generate the frozen v0.4.0a1 workspace fixture using the REAL v0.4.0a1 code (extracted from the git tag).

    python scripts/gen_v040_fixture.py            writes tests/fixtures/ws_v0_4_0a1/ (refuses to overwrite)

The fixture holds a text dump (`vep.sql`) of a schema-2 database and its CAS produced by 0.4.0a1 (signing key deliberately NOT included), the project tree
it certified, and a manifest of expected ids. tests/test_migration_fixtures.py opens it with the current code.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "fixtures" / "ws_v0_4_0a1"
TAG = "v0.4.0a1"

DRIVER = r'''
import json, shutil, sqlite3, sys
from pathlib import Path
from vep import budgets, candidates, certificates, execution, snapshots, versions
from vep.evidence import KeyStore
from vep.objectives import create_objective
from vep.policies import make_policy
from vep.workspace import Workspace
proj, out = Path(sys.argv[1]), Path(sys.argv[2])
ws = Workspace.init(proj); KeyStore(ws).ensure()
base = snapshots.take_snapshot(ws)
pol = make_policy(ws, base)
obj = create_objective(ws, "fixture", "frozen 0.4.0a1 workspace", base.id, pol.id)
budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
(proj / "extra.py").write_text("X = 1\n")
snap = snapshots.take_snapshot(ws)
cid = candidates.register_candidate(ws, obj.id, snap.id, "fixture").id
r = execution.evaluate(ws, cid, trusted_local_authorization=execution.TRUSTED_LOCAL_AUTH)
cert = certificates.certify(ws, cid)
v = certificates.verify_certificate(ws, cert.id, current_root=proj)
c = sqlite3.connect(str(ws.state / "vep.db")); c.execute("PRAGMA wal_checkpoint(TRUNCATE)"); c.close()
out.mkdir(parents=True)
src = sqlite3.connect(str(ws.state / "vep.db"))
(out / "vep.sql").write_text("\n".join(src.iterdump()) + "\n")   # text dump of the real schema-2 database (a *.db file may not be committed)
src.close()
shutil.copytree(ws.state / "cas", out / "cas")
shutil.copytree(proj, out / "project", ignore=shutil.ignore_patterns(".vep"))
json.dump({"package_version": versions.PACKAGE_VERSION, "db_schema": versions.DB_SCHEMA_VERSION, "objective_id": obj.id, "policy_id": pol.id,
           "candidate_id": cid, "snapshot_id": snap.id, "base_snapshot_id": base.id, "certificate_id": cert.id,
           "evidence_id": r["evidence_id"], "trust_level": v["trust_level"], "evaluator_id": v["evaluator_id"]}, open(out / "manifest.json", "w"), indent=1, sort_keys=True)
'''


def main() -> int:
    if OUT.exists():
        print(f"{OUT} exists; fixtures are frozen and are never overwritten", file=sys.stderr)
        return 1
    tmp = Path(tempfile.mkdtemp())
    try:
        subprocess.run(f"git -C {ROOT} archive {TAG} src | tar -x -C {tmp}", shell=True, check=True)
        proj = tmp / "project"
        shutil.copytree(ROOT / "examples" / "tiny_project", proj)
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(tmp / "src"), "HOME": str(tmp)}
        subprocess.run([sys.executable, "-c", DRIVER, str(proj), str(OUT)], check=True, env=env, cwd=tmp)
        m = json.loads((OUT / "manifest.json").read_text())
        assert m["package_version"] == "0.4.0a1" and m["db_schema"] == 2, m
        m["vep_sql_sha256"] = hashlib.sha256((OUT / "vep.sql").read_bytes()).hexdigest()
        (OUT / "manifest.json").write_text(json.dumps(m, indent=1, sort_keys=True))
        print("wrote", OUT, m["certificate_id"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
