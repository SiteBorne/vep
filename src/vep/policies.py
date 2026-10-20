"""Frozen execution/acceptance policy: validation, grammar, and candidate-change checks."""
from __future__ import annotations

import fnmatch
import re
import sys
from typing import Any

from .errors import PolicyViolation, SchemaError
from .objects import VEPObject
from .errors import SnapshotError
from .snapshots import diff, entries_of, validate_rel_path
from .workspace import Workspace

DEFAULT_PROTECTED = [
    "conftest.py", "*/conftest.py", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml",
    "unittest.cfg", ".coveragerc", "sitecustomize.py", "usercustomize.py", "*.pth", ".vep/*",
    "vep-policy*.json",
]
RUNNER_NAMES = {"pytest", "_pytest", "pluggy", "iniconfig", "packaging", "vep", "pip", "setuptools",
                "pkg_resources", "cryptography", "_pytest_plugin"}
DENIED_MODULES = frozenset(sys.stdlib_module_names) | RUNNER_NAMES
PATTERN_RE = re.compile(r"^[A-Za-z0-9_*?.\-]{1,64}$")

EVALUATOR_GRAMMAR = {
    "unittest": {"kind", "start_dir", "pattern", "import_roots", "min_tests", "allow_module_names"},
    "pytest": {"kind", "targets", "import_roots", "min_tests"},
}
DEFAULT_LIMITS = {"timeout_s": 120, "max_output_bytes": 4_000_000, "evaluation_cost_micro_usd": 1000}


def _rel(path):
    try:
        return validate_rel_path(path)
    except SnapshotError as exc:
        raise SchemaError(str(exc)) from exc


def validate_evaluator(ev: Any) -> dict:
    """Restricted command grammar: structured fields only, never a free-form command line."""
    if not isinstance(ev, dict) or ev.get("kind") not in EVALUATOR_GRAMMAR:
        raise SchemaError("evaluator.kind must be 'unittest' or 'pytest'")
    extra = set(ev) - EVALUATOR_GRAMMAR[ev["kind"]]
    if extra:
        raise SchemaError(f"evaluator has disallowed fields {sorted(extra)}")
    mt = ev.get("min_tests", 1)
    if isinstance(mt, bool) or not isinstance(mt, int) or mt < 1:
        raise SchemaError("evaluator.min_tests must be an integer >= 1 (zero-test results can never pass)")
    roots = ev.get("import_roots", ["."])
    if not isinstance(roots, list) or not roots:
        raise SchemaError("evaluator.import_roots must be a non-empty list")
    for r in roots:
        if r != ".":
            _rel(r)
    allow = ev.get("allow_module_names", [])
    if not isinstance(allow, list) or any(not isinstance(n, str) or n not in RUNNER_NAMES for n in allow):
        raise SchemaError("evaluator.allow_module_names may only list names from RUNNER_NAMES "
                          "(standard-library names can never be allowed); it applies to the unittest evaluator only")
    if ev["kind"] == "unittest":
        _rel(ev.get("start_dir", "tests"))
        if not PATTERN_RE.match(ev.get("pattern", "test*.py")):
            raise SchemaError("evaluator.pattern contains disallowed characters")
    else:
        t = ev.get("targets", ["tests"])
        if not isinstance(t, list) or not t:
            raise SchemaError("evaluator.targets must be a non-empty list")
        for x in t:
            _rel(x)
    return ev


def validate_policy(policy: VEPObject) -> None:
    if policy.type != "ExecutionPolicy":
        raise SchemaError("not an ExecutionPolicy")
    validate_evaluator(policy["evaluator"])
    limits = policy["limits"]
    if not isinstance(limits, dict):
        raise SchemaError("limits must be an object")
    for k, v in limits.items():
        if k not in DEFAULT_LIMITS or isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise SchemaError(f"invalid limit {k!r}")
    for p in policy["required_tests"]:
        _rel(p)
    if not isinstance(policy["audits"], list):
        raise SchemaError("audits must be a list")
    if not policy["required_tests"]:
        raise SchemaError("policy must freeze at least one required test file")


def make_policy(ws: Workspace, base: VEPObject, name: str = "default",
                evaluator: dict | None = None, protected: list[str] | None = None,
                audits: list | None = None, limits: dict | None = None,
                required_exclude: list[str] | None = None) -> VEPObject:
    """Build a policy from the *trusted base snapshot*; required tests are frozen by digest.

    `required_exclude` is an operator decision made here, at policy creation, never by a candidate: the listed
    test files are left out of the required set (for example a suite that is entirely skipped on this platform
    and would otherwise be rejected as ALL_SKIPPED). They still run, but are no longer protected by digest.
    Callers should record the exclusion and its reason; unknown paths are an error."""
    ev = validate_evaluator(evaluator or {"kind": "unittest", "start_dir": "tests",
                                          "pattern": "test*.py", "import_roots": ["."], "min_tests": 1})
    required = {}
    if ev["kind"] == "unittest":
        start = ev.get("start_dir", "tests")
        pat = ev.get("pattern", "test*.py")
        for p, e in entries_of(base).items():
            if p.startswith(start.rstrip("/") + "/") and fnmatch.fnmatchcase(p.rsplit("/", 1)[-1], pat):
                required[p] = e["digest"]
    else:
        for p, e in entries_of(base).items():
            if any(p == t or p.startswith(t.rstrip("/") + "/") for t in ev["targets"]) and p.endswith(".py"):
                required[p] = e["digest"]
    unknown = set(required_exclude or []) - set(required)
    if unknown:
        raise SchemaError(f"required_exclude names files that are not required tests: {sorted(unknown)}")
    for p in required_exclude or []:
        del required[p]
    pol = VEPObject.create("ExecutionPolicy", {
        "name": name, "policy_version": 1, "evaluator": ev,
        "protected_patterns": list(DEFAULT_PROTECTED if protected is None else protected),
        "required_tests": required, "limits": {**DEFAULT_LIMITS, **(limits or {})},
        "audits": audits or []})
    validate_policy(pol)
    ws.put_object(pol)
    return pol


def load_policy(ws: Workspace, policy_id: str) -> VEPObject:
    pol = ws.get_object(policy_id, "ExecutionPolicy")
    validate_policy(pol)
    return pol


def _matches(path: str, patterns: list[str]) -> bool:
    base = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase(base, p) for p in patterns)


def _import_dirs(ev: dict) -> list[str]:
    dirs = {""}
    for r in ev.get("import_roots", ["."]):
        dirs.add("" if r == "." else r.rstrip("/"))
    if ev["kind"] == "unittest":
        dirs.add(ev.get("start_dir", "tests").rstrip("/"))
    else:
        for t in ev.get("targets", []):
            dirs.add(t.rstrip("/"))
    return sorted(dirs)


def shadowing_paths(ev: dict, paths: list[str]) -> list[str]:
    bad = []
    for p in paths:
        for d in _import_dirs(ev):
            rel = p if d == "" else (p[len(d) + 1:] if p.startswith(d + "/") else None)
            if rel is None:
                continue
            first = rel.split("/")[0].split(".")[0]
            if first in DENIED_MODULES - set(ev.get("allow_module_names", [])):
                bad.append(p)
                break
    return bad


def check_candidate(policy: VEPObject, objective_base: VEPObject, cand: VEPObject) -> list[str]:
    """Return a list of violations (empty == acceptable). Pure function of frozen inputs."""
    out: list[str] = []
    d = diff(objective_base, cand)
    changed = d["added"] + d["removed"] + d["modified"] + d["mode_changed"]
    pats = policy["protected_patterns"]
    for p in changed:
        if _matches(p, pats):
            out.append(f"PROTECTED_PATH_CHANGED:{p}")
    ce = entries_of(cand)
    for p, dig in policy["required_tests"].items():
        if p not in ce:
            out.append(f"REQUIRED_TEST_MISSING:{p}")
        elif ce[p]["digest"] != dig:
            out.append(f"REQUIRED_TEST_MODIFIED:{p}")
    for p in shadowing_paths(policy["evaluator"], d["added"] + d["modified"]):
        out.append(f"RUNNER_SHADOWING:{p}")
    return sorted(set(out))


def assert_candidate_ok(policy: VEPObject, objective_base: VEPObject, cand: VEPObject) -> None:
    v = check_candidate(policy, objective_base, cand)
    if v:
        raise PolicyViolation("; ".join(v))
