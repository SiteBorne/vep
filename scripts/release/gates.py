"""Release-gate building blocks. Pure functions where possible so tests can exercise them directly.

Status vocabulary: PASS FAIL NOT_RUN UNVERIFIED NOT_APPLICABLE. A gate is PASS only if its check was
executed and succeeded in this run.
"""
from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = Path(__file__).with_name("release_policy.json")
STATUSES = ("PASS", "FAIL", "NOT_RUN", "UNVERIFIED", "NOT_APPLICABLE")


def load_policy(path: Path = POLICY_PATH) -> dict:
    return json.loads(Path(path).read_text())


def gate(status: str, detail: str = "", **extra) -> dict:
    if status not in STATUSES:
        raise ValueError(status)
    return {"status": status, "detail": detail, **extra}


# ------------------------------------------------------------------ decision
def decide(gates: dict, policy: dict) -> dict:
    """GO iff every required gate is PASS. Unknown or missing required gates count as NOT_RUN."""
    required = policy["required_gates"]
    problems = []
    for g in required:
        st = gates.get(g, {}).get("status", "NOT_RUN")
        if st not in policy["allowed_statuses"]:
            st = "FAIL"
        if st != "PASS":
            problems.append(f"{g}={st}")
    for name, g in gates.items():
        if g.get("status") not in policy["allowed_statuses"]:
            problems.append(f"{name}=INVALID_STATUS")
    caps = {}
    for cap, rule in policy["capabilities"].items():
        req = required if rule["requires_all"] == "required_gates" else rule["requires_all"]
        caps[cap] = "PASS" if all(gates.get(r, {}).get("status") == "PASS" for r in req) and not (
            cap == "PUBLIC_DEVELOPER_PREVIEW" and problems) else (
            "UNVERIFIED" if cap == "UNTRUSTED_EXECUTION_ISOLATION" else "FAIL")
    return {"decision": "GO" if not problems else "NO_GO", "blocking": problems, "capabilities": caps}


# ------------------------------------------------------------------ claims
def scan_claims(text: str, policy: dict, capabilities: dict, name: str = "") -> list[dict]:
    neg = [m.lower() for m in policy["negation_markers"]]
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(m in low for m in neg):
            continue  # negated / limiting statements are the honest form
        for rule in policy["forbidden_claims"]:
            if capabilities.get(rule["unless_capability"]) == "PASS":
                continue
            if re.search(rule["pattern"], line, re.I):
                found.append({"file": name, "line": n, "claim": rule["id"], "text": line.strip()[:160]})
    return found


# ------------------------------------------------------------------ secrets
def scan_text_for_secrets(text: str, policy: dict, name: str = "") -> list[dict]:
    out = []
    for rule in policy["secret_patterns"]:
        for m in re.finditer(rule["pattern"], text):
            line = text.count("\n", 0, m.start()) + 1
            out.append({"file": name, "line": line, "rule": rule["id"]})  # never include the matched text
    return out


def _git(*args, cwd=ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def scan_tree(policy: dict, root: Path = ROOT) -> list[dict]:
    files = _git("ls-files", "-co", "--exclude-standard", cwd=root).stdout.split("\n")
    out = []
    for f in filter(None, files):
        p = root / f
        if not p.is_file() or p.stat().st_size > 5_000_000:
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        out += scan_text_for_secrets(text, policy, f)
        if any(fnmatch.fnmatch(p.name, g) for g in policy["forbidden_artifact_names"]):
            out.append({"file": f, "line": 0, "rule": "FORBIDDEN_FILENAME_IN_SOURCE_TREE"})
    return out


def scan_history(policy: dict, root: Path = ROOT) -> list[dict]:
    """Scan every blob reachable from any ref, not just the working tree."""
    revs = _git("rev-list", "--all", cwd=root).stdout.split()
    seen, out = set(), []
    for rev in revs:
        for line in _git("ls-tree", "-r", "-z", rev, cwd=root).stdout.split("\0"):
            if not line:
                continue
            meta, _, path = line.partition("\t")
            sha = meta.split()[2]
            if sha in seen:
                continue
            seen.add(sha)
            blob = subprocess.run(["git", "cat-file", "blob", sha], cwd=root, capture_output=True).stdout
            if len(blob) > 5_000_000 or b"\0" in blob[:2048]:
                continue
            hits = scan_text_for_secrets(blob.decode("utf-8", "ignore"), policy, f"{rev[:10]}:{path}")
            out += hits
            if any(fnmatch.fnmatch(Path(path).name, g) for g in policy["forbidden_artifact_names"]):
                out.append({"file": f"{rev[:10]}:{path}", "line": 0, "rule": "FORBIDDEN_FILENAME_IN_HISTORY"})
    return out


# ------------------------------------------------------------------ artifacts
def iter_artifact_members(path: Path):
    """Yield (member name, bytes|None) for wheel (zip) or sdist (tar.gz)."""
    path = Path(path)
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                yield i.filename, (None if i.is_dir() else z.read(i))
    else:
        with tarfile.open(path, "r:gz") as t:
            for m in t.getmembers():
                if m.isfile():
                    yield m.name, t.extractfile(m).read()


def audit_artifact(path: Path, policy: dict) -> list[str]:
    problems = []
    for name, data in iter_artifact_members(path):
        parts = name.split("/")
        base = parts[-1]
        if any(p in policy["forbidden_artifact_dirs"] for p in parts[:-1]):
            problems.append(f"{name}: forbidden directory")
        if any(fnmatch.fnmatch(base, g) for g in policy["forbidden_artifact_names"]):
            problems.append(f"{name}: forbidden file name")
        if data is None:
            continue
        text = data.decode("utf-8", "ignore") if b"\0" not in data[:2048] else ""
        for s in scan_text_for_secrets(text, policy, name):
            problems.append(f"{name}:{s['line']}: secret pattern {s['rule']}")
        for needle in (unquote(n) for n in policy["forbidden_artifact_text"]):
            if needle in text:
                problems.append(f"{name}: machine-specific path {needle!r}")
    return problems


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_checksums(files: list[Path], out: Path) -> None:
    out.write_text("".join(f"{sha256_file(f)}  {f.name}\n" for f in sorted(files)))


def verify_checksums(manifest: Path) -> list[str]:
    bad = []
    for line in manifest.read_text().splitlines():
        digest, _, name = line.partition("  ")
        f = manifest.parent / name
        if not f.is_file() or sha256_file(f) != digest:
            bad.append(name)
    return bad


# ------------------------------------------------------------------ workflows
def lint_workflow(text: str, policy: dict, name: str = "") -> list[str]:
    """Static checks without a YAML dependency: pinned actions, explicit permissions, forbidden triggers."""
    rules = policy["workflow_rules"]
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        m = re.match(r"-?\s*uses:\s*([^\s#]+)", s)
        if m and not m.group(1).startswith("./"):
            ref = m.group(1).rpartition("@")[2]
            if not re.match(rules["pinned_sha_regex"], ref):
                problems.append(f"{name}:{n}: action not pinned to a full commit SHA: {m.group(1)}")
        for trig in rules["forbid_triggers"]:
            if re.match(rf"^{trig}\s*:", s):
                problems.append(f"{name}:{n}: forbidden trigger {trig}")
    if rules["require_top_level_permissions"] and not re.search(r"^permissions:", text, re.M):
        problems.append(f"{name}: no top-level 'permissions:' block")
    if re.search(r"^permissions:\s*write-all", text, re.M):
        problems.append(f"{name}: write-all permissions")
    return problems


# ------------------------------------------------------------------ docs / versions
def version_consistency(root: Path = ROOT) -> dict:
    import re as _re
    py = (root / "pyproject.toml").read_text()
    v = {"pyproject": _re.search(r'^version\s*=\s*"([^"]+)"', py, _re.M).group(1)}
    v["__init__"] = _re.search(r'__version__\s*=\s*"([^"]+)"', (root / "src/vep/__init__.py").read_text()).group(1)
    v["versions.py"] = _re.search(r'PACKAGE_VERSION\s*=\s*"([^"]+)"', (root / "src/vep/versions.py").read_text()).group(1)
    ch = (root / "CHANGELOG.md").read_text()
    m = _re.search(r"^## \[([^\]]+)\]", ch, _re.M)
    v["CHANGELOG"] = m.group(1) if m else "MISSING"
    return v


def parse_security_findings(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        if line.startswith("| SR-"):
            c = [x.strip() for x in line.strip("|").split("|")]
            if len(c) >= 9:
                rows.append(dict(zip(["id", "severity", "preconditions", "component", "root_cause", "mitigation",
                                      "regression_test", "residual", "status"], c)))
    return rows


def check_security_findings(rows: list[dict], root: Path = ROOT) -> list[str]:
    problems = []
    if not rows:
        return ["no findings table"]
    for r in rows:
        if r["status"] not in ("FIXED", "MITIGATED", "ACCEPTED_RESIDUAL", "NOT_APPLICABLE"):
            problems.append(f"{r['id']}: status {r['status']}")
        if r["severity"] in ("CRITICAL", "HIGH") and r["status"] not in ("FIXED", "MITIGATED"):
            problems.append(f"{r['id']}: {r['severity']} finding not fixed/mitigated")
        if r["status"] in ("FIXED", "MITIGATED"):
            tests = re.findall(r"`(tests/\w+\.py)::(\w+)\.(\w+)`", r["regression_test"])
            if not tests:
                problems.append(f"{r['id']}: no regression test reference")
            for path, cls, meth in tests:
                f = root / path
                if not f.is_file() or not re.search(rf"def {meth}\(", f.read_text()):
                    problems.append(f"{r['id']}: missing test {path}::{cls}.{meth}")
    return problems


def run(cmd, cwd=ROOT, timeout=1800, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)
