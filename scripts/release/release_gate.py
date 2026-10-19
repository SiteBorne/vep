"""Deterministic release qualification. Writes release-gate.json and docs/RELEASE_GATE_REPORT.md.

    python scripts/release/release_gate.py [--skip-matrix] [--no-write]

Exit status 0 iff the derived decision is GO. Every gate reports PASS/FAIL/NOT_RUN/UNVERIFIED/NOT_APPLICABLE.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gates as G  # noqa: E402

ROOT = G.ROOT
PY = sys.executable
OUT_JSON = ROOT / "release-gate.json"
OUT_MD = ROOT / "docs" / "RELEASE_GATE_REPORT.md"
OUTPUT_PATHS = {"release-gate.json", "docs/RELEASE_GATE_REPORT.md"}
MATRIX_PYTHONS = ["3.11", "3.12", "3.13", "3.14"]


def count_line(out: str, pat: str) -> int | None:
    m = re.search(pat, out)
    return int(m.group(1)) if m else None


class Ctx:
    def __init__(self) -> None:
        self.policy = G.load_policy()
        self.tmp = Path(tempfile.mkdtemp(prefix="vep-release-"))
        self.results: dict = {}
        self.wheel: Path | None = None
        self.sdist: Path | None = None
        self.wheel_venv: Path | None = None
        self.sdist_venv: Path | None = None
        self.facts: dict = {}

    def venv(self, name: str, python: str = PY) -> Path:
        v = self.tmp / name
        r = G.run([python, "-m", "venv", str(v)])
        if r.returncode:
            raise RuntimeError(r.stderr)
        return v


# ------------------------------------------------------------------ gates
def g_source(c: Ctx):
    git = G.run(["git", "rev-parse", "HEAD"])
    if git.returncode:
        return G.gate("FAIL", "not a git repository")
    commit = git.stdout.strip()
    tree = G.run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip()
    status = G.run(["git", "status", "--porcelain", "--untracked-files=all"]).stdout.splitlines()
    dirty = [l for l in status if l[3:].strip() not in OUTPUT_PATHS]
    v = G.version_consistency()
    c.facts.update(commit=commit, tree=tree, version=v["pyproject"])
    problems = []
    if dirty:
        problems.append(f"{len(dirty)} uncommitted/untracked paths (first: {dirty[0]})")
    if len(set(v.values())) != 1:
        problems.append(f"version mismatch {v}")
    tag = G.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/v{v['pyproject']}^{{commit}}"])
    if tag.returncode == 0 and tag.stdout.strip() != commit:
        problems.append("release tag exists but does not point at HEAD")
    if not (ROOT / "LICENSE").is_file():
        problems.append("LICENSE missing")
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems) or f"clean tree at {commit[:12]}, version {v['pyproject']}",
                  commit=commit, tree=tree, versions=v)


def g_discovery(c: Ctx):
    code = ("import unittest,sys;s=unittest.TestLoader().discover('tests',top_level_dir='.');print(s.countTestCases())")
    u = G.run([PY, "-c", code])
    p = G.run([PY, "-m", "pytest", "--collect-only", "-q"])
    nu = int(u.stdout.strip() or 0) if u.returncode == 0 else -1
    npy = count_line(p.stdout, r"(\d+) tests? collected")
    c.facts.update(discovered_unittest=nu, discovered_pytest=npy)
    ok = nu > 0 and nu == npy
    return G.gate("PASS" if ok else "FAIL", f"unittest={nu} pytest={npy}", unittest=nu, pytest=npy)


def g_units(c: Ctx):
    u = G.run([PY, "-m", "unittest", "discover", "-s", "tests", "-t", "."])
    p = G.run([PY, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider"])
    ran = count_line(u.stderr, r"Ran (\d+) tests?")
    skipped_u = count_line(u.stderr, r"skipped=(\d+)") or 0
    passed = count_line(p.stdout, r"(\d+) passed")
    failed = count_line(p.stdout, r"(\d+) failed") or 0
    skipped_p = count_line(p.stdout, r"(\d+) skipped") or 0
    c.facts.update(unittest_ran=ran, pytest_passed=passed)
    ok = (u.returncode == 0 and "\nOK" in u.stderr and p.returncode == 0 and ran and ran == passed
          and not skipped_u and not skipped_p and not failed)
    return G.gate("PASS" if ok else "FAIL", f"unittest ran={ran} rc={u.returncode} skipped={skipped_u}; pytest passed={passed} "
                  f"failed={failed} skipped={skipped_p}", unittest_ran=ran, pytest_passed=passed, failed=failed,
                  skipped=skipped_u + skipped_p, not_run=0)


def _mods(mods, label):
    r = G.run([PY, "-m", "unittest", *mods])
    ran = count_line(r.stderr, r"Ran (\d+) tests?")
    ok = r.returncode == 0 and "\nOK" in r.stderr and ran and "skipped" not in r.stderr
    return G.gate("PASS" if ok else "FAIL", f"{label}: ran={ran} rc={r.returncode}", ran=ran, tail=r.stderr[-400:] if not ok else "")


def g_adversarial(c):
    return _mods(["tests.test_adversarial", "tests.test_trust", "tests.test_isolation", "tests.test_isolation_matrix",
                  "tests.test_release"], "adversarial+trust+isolation+release regression")


def g_invariants(c):
    return _mods(["tests.test_docs", "tests.test_canonical", "tests.test_storage", "tests.test_snapshots", "tests.test_candidates",
                  "tests.test_budgets", "tests.test_certificates", "tests.test_policies"], "invariant suites")


def g_demo(c):
    r = G.run([PY, "examples/run_demo.py"])
    ok = r.returncode == 0 and "DEMO OK" in r.stdout and "rejected: SOURCE_CHANGED" in r.stdout
    return G.gate("PASS" if ok else "FAIL", f"rc={r.returncode}")


def g_sim(c):
    a, b = (G.run([PY, "-m", "vep", "simulate", "--tasks", "2000", "--seed", "20261019", "--sensitivity", "--json"]) for _ in range(2))
    bench = G.run([PY, "benchmarks/run_simulation.py", "--tasks", "2000", "--out-json", str(c.tmp / "b.json"), "--out-md", str(c.tmp / "b.md")])
    ok = a.returncode == 0 and a.stdout == b.stdout and len(a.stdout) > 1000 and bench.returncode == 0 and "reproducible: yes" in bench.stdout
    h = re.search(r'"result_sha256": "([0-9a-f]+)"', a.stdout)
    return G.gate("PASS" if ok else "FAIL", f"identical={a.stdout == b.stdout}", result_sha256=h.group(1) if h else None,
                  classification="SYNTHETIC")


def g_build(c):
    dist = ROOT / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    r = G.run([PY, "-m", "build", "--outdir", str(dist)])
    wheels, sdists = list(dist.glob("*.whl")), list(dist.glob("*.tar.gz"))
    if r.returncode or len(wheels) != 1 or len(sdists) != 1:
        return G.gate("FAIL", f"build rc={r.returncode} wheels={len(wheels)} sdists={len(sdists)}\n{r.stderr[-500:]}")
    c.wheel, c.sdist = wheels[0], sdists[0]
    v = c.facts.get("version") or G.version_consistency()["pyproject"]
    tw = G.run([PY, "-m", "twine", "check", "--strict", str(c.wheel), str(c.sdist)])
    ok = tw.returncode == 0 and f"-{v}-" in c.wheel.name and c.sdist.name.endswith(f"-{v}.tar.gz")
    return G.gate("PASS" if ok else "FAIL", f"{c.wheel.name}, {c.sdist.name}; twine check rc={tw.returncode} {tw.stdout[-200:]}{tw.stderr[-200:]}")


def g_install(c):
    if not c.wheel:
        return G.gate("NOT_RUN", "no artifacts")
    c.wheel_venv = c.venv("wheel-venv")
    r = G.run([str(c.wheel_venv / "bin" / "pip"), "install", "--no-cache-dir", str(c.wheel)])
    chk = G.run([str(c.wheel_venv / "bin" / "pip"), "check"])
    # sdist installation in a second clean env
    c.sdist_venv = c.venv("sdist-venv")
    r2 = G.run([str(c.sdist_venv / "bin" / "pip"), "install", "--no-cache-dir", str(c.sdist)])
    ver = G.run([str(c.wheel_venv / "bin" / "vep"), "version", "--json"], cwd=c.tmp)
    ver2 = G.run([str(c.sdist_venv / "bin" / "vep"), "version", "--json"], cwd=c.tmp)
    ok = all(x.returncode == 0 for x in (r, chk, r2, ver, ver2)) and json.loads(ver.stdout)["package"] == c.facts["version"] \
        and json.loads(ver2.stdout)["package"] == c.facts["version"]
    return G.gate("PASS" if ok else "FAIL", f"wheel install rc={r.returncode}; pip check rc={chk.returncode}; sdist install rc={r2.returncode}\n"
                  + (r.stderr + r2.stderr)[-400:] if not ok else "wheel and sdist install cleanly; pip check ok")


def g_cli(c):
    if not c.wheel_venv:
        return G.gate("NOT_RUN", "no installed wheel")
    r = G.run([PY, "scripts/release/cleanroom.py", "--venv", str(c.wheel_venv)])
    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError:
        return G.gate("FAIL", "cleanroom produced no JSON: " + r.stderr[-300:])
    bad = [x for x in doc["checks"] if x["status"] != "PASS"]
    return G.gate("PASS" if doc["status"] == "PASS" and r.returncode == 0 else "FAIL",
                  f"{len(doc['checks'])} clean-room checks; failing: {[x['check'] for x in bad]}", checks=len(doc["checks"]))


def g_artifacts(c):
    if not c.wheel:
        return G.gate("NOT_RUN", "no artifacts")
    files = [c.wheel, c.sdist]
    sums = c.wheel.parent / "SHA256SUMS"
    G.write_checksums(files, sums)
    bad = G.verify_checksums(sums)
    problems = [f"checksum mismatch {bad}"] if bad else []
    for f in files:
        problems += [f"{f.name}: {p}" for p in G.audit_artifact(f, c.policy)]
    names = [n for n, _ in G.iter_artifact_members(c.wheel)]
    for need in ("vep/_runner.py", "vep/_isolation_probe.py", "vep/cli.py"):
        if need not in names:
            problems.append(f"wheel missing {need}")
    meta = next(n for n in names if n.endswith("METADATA"))
    with zipfile.ZipFile(c.wheel) as z:
        md = z.read(meta).decode()
        entry = z.read(next(n for n in names if n.endswith("entry_points.txt"))).decode()
        lic = [n for n in names if "LICENSE" in n]
    if f"Version: {c.facts['version']}" not in md or "Name: vep-protocol" not in md:
        problems.append("wheel metadata name/version mismatch")
    if "License-Expression: Apache-2.0" not in md and "License: Apache-2.0" not in md:
        problems.append("license metadata missing")
    if "Requires-Python: >=3.11" not in md:
        problems.append("Requires-Python metadata missing")
    if "vep = vep.cli:main" not in entry:
        problems.append("console entry point missing")
    if not lic:
        problems.append("LICENSE not packaged in wheel")
    with tarfile.open(c.sdist) as t:
        sn = t.getnames()
    for need in ("LICENSE", "README.md", "pyproject.toml", "tests/test_adversarial.py", "docs/RFC-0001.md"):
        if not any(n.endswith("/" + need) for n in sn):
            problems.append(f"sdist missing {need}")
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems[:6]) or "checksums verified; no keys/db/env/machine paths/secrets in wheel or sdist",
                  artifacts={f.name: G.sha256_file(f) for f in files})


def g_secrets(c):
    hits = G.scan_tree(c.policy) + G.scan_history(c.policy)
    return G.gate("FAIL" if hits else "PASS", f"{len(hits)} findings" + (f" (first: {hits[0]['rule']} in {hits[0]['file']}:{hits[0]['line']})" if hits else
                  "; working tree, all reachable history and release artifacts scanned (values are never printed)"))


def g_security(c):
    p = ROOT / "docs" / "SECURITY_REVIEW.md"
    if not p.is_file():
        return G.gate("FAIL", "docs/SECURITY_REVIEW.md missing")
    rows = G.parse_security_findings(p.read_text())
    problems = G.check_security_findings(rows)
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems[:5]) or f"{len(rows)} findings recorded, none open; each fixed/mitigated finding has an existing regression test",
                  findings=len(rows))


def g_docs(c):
    problems = []
    for d in c.policy["required_docs"]:
        f = ROOT / d
        if not f.is_file() or f.stat().st_size < 200:
            problems.append(f"missing/empty {d}")
    claims = []
    caps = {"UNTRUSTED_EXECUTION_ISOLATION": "UNVERIFIED"}
    for pat in c.policy["claim_scan_paths"]:
        for f in sorted(ROOT.glob(pat)):
            if f.name in ("RELEASE_GATE_REPORT.md",):
                continue
            claims += G.scan_claims(f.read_text(), c.policy, caps, str(f.relative_to(ROOT)))
    problems += [f"{x['file']}:{x['line']} {x['claim']}" for x in claims]
    if c.wheel_venv:
        r = G.run([PY, "scripts/release/quickstart_runner.py", "--bin-dir", str(c.wheel_venv / "bin")])
        if r.returncode:
            problems.append("quickstart commands failed: " + (r.stdout + r.stderr)[-300:])
        qs = "quickstart executed against installed wheel"
    else:
        problems.append("quickstart not run")
        qs = ""
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems[:6]) or f"{len(c.policy['required_docs'])} required docs present; no unsupported claims; {qs}")


def g_compat(c):
    g = _mods(["tests.test_compat"], "frozen-fixture compatibility")
    h = G.sha256_file(ROOT / "tests" / "fixtures" / "legacy_v1_objects.json")
    return {**g, "fixture_sha256": h}


def g_provenance(c):
    if not c.wheel:
        return G.gate("NOT_RUN", "no artifacts")
    problems = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        problems += G.lint_workflow(wf.read_text(), c.policy, wf.name)
    if not (ROOT / "docs" / "RELEASE_PROVENANCE.md").is_file():
        problems.append("docs/RELEASE_PROVENANCE.md missing")
    rec = {"record_type": "vep-local-build-record/v1",
           "disclaimer": "Local record of what was built and tested. It is NOT an in-toto/SLSA attestation and claims no SLSA level.",
           "source": {"commit": c.facts["commit"], "tree": c.facts["tree"], "version": c.facts["version"]},
           "artifacts": [{"name": f.name, "sha256": G.sha256_file(f), "bytes": f.stat().st_size} for f in (c.wheel, c.sdist)],
           "build_environment": {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine()},
           "gates_before_provenance": {k: {"status": v["status"]} for k, v in c.results.items()},
           "hosted_attestation": "NOT_RUN (produced only by the GitHub release workflow)"}
    path = c.wheel.parent / "release-provenance.json"
    path.write_text(json.dumps(rec, indent=1, sort_keys=True))
    again = json.loads(path.read_text())
    for a in again["artifacts"]:
        if G.sha256_file(c.wheel.parent / a["name"]) != a["sha256"]:
            problems.append(f"provenance hash mismatch {a['name']}")
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems[:5]) or "local build record written and re-verified; workflows pass static checks (SHA-pinned, least-privilege, no pull_request_target); hosted attestation NOT_RUN",
                  workflows=[w.name for w in (ROOT / ".github" / "workflows").glob("*.yml")])


def g_pycompat(c, skip=False):
    if skip or not c.sdist:
        return G.gate("NOT_RUN", "skipped by --skip-matrix" if skip else "no sdist")
    out, problems = {}, []
    ex = c.tmp / "sdist-src"
    with tarfile.open(c.sdist) as t:
        t.extractall(ex, filter="data")
    srcdir = next(ex.iterdir())
    for ver in MATRIX_PYTHONS:
        exe = shutil.which(f"python{ver}") or (f"/opt/homebrew/bin/python{ver}" if Path(f"/opt/homebrew/bin/python{ver}").exists() else None)
        if not exe:
            out[ver] = "NOT_RUN (interpreter not installed)"
            problems.append(f"python{ver} unavailable")
            continue
        v = c.venv(f"py{ver}", exe)
        pip = str(v / "bin" / "pip")
        r = G.run([pip, "install", "-q", "--no-cache-dir", str(c.wheel), "pytest"])
        if r.returncode:
            out[ver] = "FAIL (install)"; problems.append(f"{ver} install"); continue
        t = G.run([str(v / "bin" / "python"), "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=srcdir)
        ran = count_line(t.stderr, r"Ran (\d+) tests?")
        good = t.returncode == 0 and "\nOK" in t.stderr and "skipped" not in t.stderr
        out[ver] = f"{'PASS' if good else 'FAIL'} ran={ran}"
        if not good:
            problems.append(f"{ver}: {t.stderr[-300:]}")
    return G.gate("FAIL" if problems else "PASS", "; ".join(problems[:3]) or "tests run from the extracted sdist against the installed wheel on every supported interpreter",
                  versions=out)


def g_isolation(c):
    sys.path.insert(0, str(ROOT / "src"))
    from vep import isolation
    image = os.environ.get("VEP_ISOLATION_IMAGE")
    caps = isolation.detect_capabilities(image)
    if not image:
        return G.gate("UNVERIFIED", "no VEP_ISOLATION_IMAGE configured; capability report only", capabilities=caps,
                      untrusted_code_claim="NOT ALLOWED")
    att = isolation.verify_runtime(image)
    st = "PASS" if att["status"] == "ISOLATED_VERIFIED" else "UNVERIFIED"
    return G.gate(st, "; ".join(att["reasons"]) or "T1-T12 observed PASS", capabilities=caps,
                  matrix={k: v["status"] for k, v in att["results"].items()})


def g_depaudit(c):
    if not c.wheel_venv or not shutil.which("pip-audit"):
        return G.gate("NOT_RUN", "pip-audit or installed venv unavailable")
    r = G.run(["pip-audit", "--path", str(next((c.wheel_venv / "lib").glob("python*/site-packages"))), "--progress-spinner", "off"], timeout=300)
    if "ConnectionError" in r.stderr or "Max retries" in r.stderr or "Name or service" in r.stderr:
        return G.gate("NOT_RUN", "vulnerability database unreachable")
    return G.gate("PASS" if r.returncode == 0 else "FAIL", (r.stdout + r.stderr).strip()[-300:])


ORDER = [("SOURCE_INTEGRITY", g_source), ("TEST_DISCOVERY", g_discovery), ("UNIT_TESTS", g_units),
         ("ADVERSARIAL_TESTS", g_adversarial), ("INVARIANT_TESTS", g_invariants), ("DEMO", g_demo),
         ("SIMULATION_REPRODUCIBILITY", g_sim), ("PACKAGE_BUILD", g_build), ("PACKAGE_INSTALLATION", g_install),
         ("CLI_SMOKE_TEST", g_cli), ("ARTIFACT_INTEGRITY", g_artifacts), ("SECRET_SCAN", g_secrets),
         ("SECURITY_REVIEW", g_security), ("DOCUMENTATION", g_docs), ("PROTOCOL_COMPATIBILITY", g_compat),
         ("PYTHON_COMPATIBILITY", None), ("RELEASE_PROVENANCE", g_provenance), ("OPTIONAL_ISOLATION", g_isolation),
         ("DEPENDENCY_AUDIT", g_depaudit)]


def render_md(doc: dict) -> str:
    L = ["# Release Gate Report", "",
         f"**Decision: {doc['decision']}**  ·  package `{doc['package']} {doc['version']}`  ·  source `{doc['source_commit']}`", "",
         f"Generated {doc['generated_at']} on {doc['environment']['platform']} / Python {doc['environment']['python']}. "
         "Produced by `scripts/release_check.sh`; machine-readable twin: `release-gate.json`.", ""]
    if doc["blocking"]:
        L += ["**Blocking:** " + ", ".join(doc["blocking"]), ""]
    L += ["## Capabilities", "", "| Capability | Status |", "|---|---|"] + [f"| {k} | {v} |" for k, v in doc["capabilities"].items()]
    L += ["", "## Gates", "", "| Gate | Required | Status | Detail |", "|---|---|---|---|"]
    for k, v in doc["gates"].items():
        req = "yes" if k in doc["required_gates"] else "no"
        L.append(f"| {k} | {req} | **{v['status']}** | {v['detail'].replace('|', '/').replace(chr(10), ' ')[:300]} |")
    L += ["", "`PASS` = executed and succeeded in this run. `UNVERIFIED`/`NOT_RUN` are never green. Optional gates never "
          "turn a NO_GO into a GO and never upgrade a capability claim.", ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-matrix", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    a = ap.parse_args()
    c = Ctx()
    t0 = time.time()
    try:
        for name, fn in ORDER:
            t = time.time()
            try:
                res = fn(c) if name != "PYTHON_COMPATIBILITY" else g_pycompat(c, a.skip_matrix)
            except Exception as exc:
                res = G.gate("FAIL", f"gate crashed: {exc!r}\n{traceback.format_exc()[-400:]}")
            res["seconds"] = round(time.time() - t, 1)
            c.results[name] = res
            print(f"{name:28s} {res['status']:10s} {res['detail'].splitlines()[0][:110] if res['detail'] else ''}", flush=True)
        for name in ("HOSTED_CI", "HOSTED_ATTESTATION"):
            c.results[name] = G.gate("NOT_RUN", "requires the public GitHub repository; not executed locally")
        dec = G.decide(c.results, c.policy)
        doc = {"schema": "vep-release-gate/1", "package": c.policy["package"], "version": c.facts.get("version"),
               "source_commit": c.facts.get("commit"), "source_tree": c.facts.get("tree"),
               "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "environment": {"python": platform.python_version(), "platform": platform.platform()},
               "required_gates": c.policy["required_gates"], "gates": c.results, **dec,
               "test_counts": {"unittest": c.facts.get("unittest_ran"), "pytest": c.facts.get("pytest_passed"),
                               "discovered": c.facts.get("discovered_unittest")},
               "elapsed_seconds": round(time.time() - t0, 1)}
        if not a.no_write:
            OUT_JSON.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
            OUT_MD.write_text(render_md(doc))
        print(f"\nDECISION: {dec['decision']}  capabilities: {dec['capabilities']}")
        if dec["blocking"]:
            print("BLOCKING:", ", ".join(dec["blocking"]))
        return 0 if dec["decision"] == "GO" else 1
    finally:
        shutil.rmtree(c.tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
