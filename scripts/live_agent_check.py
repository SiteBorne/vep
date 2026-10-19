"""Bounded live check of the Ollama adapter against a local model. Prints a JSON report; not part of the test suite.

Usage: python scripts/live_agent_check.py MODEL [timeout_s]
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from vep import agents, budgets, controller, execution, snapshots  # noqa: E402
from vep.evidence import KeyStore  # noqa: E402
from vep.objectives import create_objective  # noqa: E402
from vep.policies import make_policy  # noqa: E402
from vep.workspace import Workspace  # noqa: E402

model = sys.argv[1]
timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 600
root = pathlib.Path(tempfile.mkdtemp()) / "p"
(root / "tests").mkdir(parents=True)
(root / "m.py").write_text("def add(a, b):\n    return a + b\n")
(root / "tests/test_m.py").write_text(
    "import unittest\nfrom m import add, sub\n\n\nclass T(unittest.TestCase):\n"
    "    def test_add(self):\n        self.assertEqual(add(1, 2), 3)\n"
    "    def test_sub(self):\n        self.assertEqual(sub(3, 1), 2)\n")
ws = Workspace.init(root)
KeyStore(ws).ensure()
base = snapshots.take_snapshot(ws)
pol = make_policy(ws, base)
obj = create_objective(ws, "add sub", "make tests pass", base.id, pol.id)
budgets.create_account(ws, f"objective:{obj.id}", "objective", "1.00")
task = agents.AgentTask(obj.id, base.id, pol.id,
                        "tests/test_m.py needs m.sub(a, b) returning a - b. Rewrite m.py so all tests pass; keep add.",
                        {"context_paths": "m.py,tests/test_m.py"}, timeout_s=timeout)
t0 = time.time()
r = agents.run_agent_task(ws, agents.OllamaAdapter(model), task, "ollama-live")
out = {k: r.get(k) for k in ("status", "error_class", "changes", "usage", "candidate_id", "detail")}
if r["candidate_id"]:
    controller.enqueue(ws, r["candidate_id"])
    out["controller"] = controller.run_one(ws, controller.LocalToolWorker("live", execution.TRUSTED_LOCAL_AUTH))
out["elapsed_s"] = round(time.time() - t0, 1)
out["model"] = model
print(json.dumps(out, indent=1, default=str))
