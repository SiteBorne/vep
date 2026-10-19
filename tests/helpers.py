"""Shared test fixtures. Everything here drives the real implementation."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from vep import budgets, candidates, execution, snapshots
from vep.evidence import KeyStore
from vep.objectives import create_objective
from vep.policies import make_policy
from vep.workspace import Workspace

BASE_FILES = {
    "arithmetic.py": "def add(a, b):\n    return a + b\n",
    "tests/test_arithmetic.py": (
        "import unittest\nfrom arithmetic import add\n\n\n"
        "class T(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n\n"
        "    def test_add_neg(self):\n        self.assertEqual(add(-1, 1), 0)\n"),
    "status.json": '{"ready": true, "credentials": {"present": true}, "components": {"a": {"ready": true}}}\n',
}
AUTH = execution.TRUSTED_LOCAL_AUTH


def src_env() -> dict:
    """Environment for child processes that must run the *same* vep source tree the tests import.

    Without this, a child `python -m vep` resolves whatever vep is installed, so an evaluation of a staged
    candidate could silently test an installed copy instead of the candidate."""
    import os
    import vep
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(Path(vep.__file__).resolve().parent.parent)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


def write_tree(root: Path, files: dict[str, str | None]) -> None:
    for rel, content in files.items():
        p = root / rel
        if content is None:
            if p.exists():
                p.unlink()
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


class Env:
    def __init__(self, tmp: Path, files=None, evaluator=None, audits=None, limits=None, budget="1.00"):
        self.tmp = tmp
        self.root = tmp / "project"
        self.files = dict(files or BASE_FILES)
        self.root.mkdir()
        write_tree(self.root, self.files)
        self.ws = Workspace.init(self.root)
        self.keystore = KeyStore(self.ws)
        self.keystore.ensure()
        self.base = snapshots.take_snapshot(self.ws)
        self.policy = make_policy(self.ws, self.base, evaluator=evaluator, audits=audits, limits=limits)
        self.objective = create_objective(self.ws, "obj", "desc", self.base.id, self.policy.id)
        self.n = 0
        if budget is not None:
            budgets.create_account(self.ws, f"objective:{self.objective.id}", "objective", budget)

    def variant(self, changes: dict[str, str | None]) -> Path:
        self.n += 1
        d = self.tmp / f"variant{self.n}"
        shutil.copytree(self.root, d, ignore=shutil.ignore_patterns(".vep"))
        write_tree(d, changes)
        return d

    def candidate(self, changes: dict[str, str | None] | None = None, author="agent") -> str:
        d = self.variant(changes or {})
        snap = snapshots.take_snapshot(self.ws, d)
        self.last_dir = d
        return candidates.register_candidate(self.ws, self.objective.id, snap.id, author).id

    def evaluate(self, cid: str, **kw):
        kw.setdefault("trusted_local_authorization", AUTH)
        return execution.evaluate(self.ws, cid, **kw)


class VepTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="vep-test-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def env(self, **kw) -> Env:
        return Env(self.tmp, **kw)
