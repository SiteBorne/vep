"""Operational fault injection: real process kills, real SQLite contention, lost responses, missing optional dependencies, forged reports.
Items already covered elsewhere are mapped in docs/FAULT_INJECTION.md (a test there checks every mapped test exists)."""
import json
import multiprocessing as mp
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import httpx

from tests.helpers import AUTH, VepTestCase, src_env
from tests.test_a2a_server import A2ABase, SLOW_TEST, TOKEN, data_msg
from vep import budgets, candidates, controller
from vep.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]


def _crash_worker(root: str, ready) -> None:
    ws = Workspace(root)
    controller.run_one(ws, controller.LocalToolWorker("doomed", AUTH), lease_s=2)


class CrashTests(VepTestCase):
    def test_sigkill_of_a_real_worker_mid_evaluation_is_recovered_without_retry_or_false_certificate(self):
        e = self.env()
        cid = e.candidate({"tests/test_slow.py": "import time, unittest\n\n\nclass S(unittest.TestCase):\n    def test_slow(self):\n        time.sleep(60)\n"})
        job = controller.enqueue(e.ws, cid)["id"]
        p = mp.get_context("spawn").Process(target=_crash_worker, args=(str(e.root), None))
        p.start()
        for _ in range(200):
            if candidates.get_state(e.ws, cid)["status"] == "EVALUATING":
                break
            time.sleep(0.1)
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "EVALUATING")
        os.kill(p.pid, signal.SIGKILL)
        p.join(10)
        time.sleep(2.5)  # lease expiry
        actions = controller.recover(e.ws)
        self.assertEqual(actions[0]["action"], "FAILED_UNKNOWN_OUTCOME")
        j = controller.get_job(e.ws, job)
        self.assertEqual((j["state"], j["failure_class"]), ("FAILED", "WORKER_LOST_AFTER_EXECUTION_STARTED"))
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "REJECTED")  # never left stuck, never certified
        self.assertEqual(budgets.get_reservation(e.ws, f"eval:{cid}")["state"], "UNCERTAIN")  # funds held, not silently refunded
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 0)
        self.assertIsNone(controller.claim(e.ws, "replacement"))  # a lost-outcome job is not re-run automatically
        self.assertEqual(controller.recover(e.ws), [])  # recovery is repeatable


def _hammer(root: str, n: int, tag: str, q) -> None:
    ws = Workspace(root)
    errs = 0
    for i in range(n):
        try:
            with ws.db.tx() as c:
                c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (f"fi:{tag}:{i}", str(i)))
        except Exception:  # noqa: BLE001
            errs += 1
    q.put(errs)


def _die_in_tx(root: str) -> None:
    ws = Workspace(root)
    with ws.db.tx() as c:
        c.execute("INSERT INTO meta(key,value) VALUES('fi:uncommitted','x')")
        os._exit(9)  # hard exit with the transaction open


class DatabaseFaultTests(VepTestCase):
    def test_sqlite_contention_from_six_processes_loses_no_writes_and_raises_no_lock_errors(self):
        e = self.env()
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        procs = [ctx.Process(target=_hammer, args=(str(e.root), 80, f"p{i}", q)) for i in range(6)]
        [p.start() for p in procs]
        errs = [q.get(timeout=120) for _ in procs]
        [p.join(30) for p in procs]
        self.assertEqual(errs, [0] * 6)
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM meta WHERE key LIKE 'fi:p%'").fetchone()["n"], 6 * 80)

    def test_a_process_killed_inside_a_transaction_leaves_no_partial_state(self):
        e = self.env()
        p = mp.get_context("spawn").Process(target=_die_in_tx, args=(str(e.root),))
        p.start(); p.join(30)
        self.assertEqual(p.exitcode, 9)
        with e.ws.db.read() as c:
            self.assertIsNone(c.execute("SELECT 1 FROM meta WHERE key='fi:uncommitted'").fetchone())
            self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        with e.ws.db.tx() as c:  # and the database is immediately writable again (no stale lock)
            c.execute("INSERT INTO meta(key,value) VALUES('fi:after','1')")

    def test_an_exception_inside_a_transaction_rolls_back_every_statement(self):
        e = self.env()
        with self.assertRaises(RuntimeError):
            with e.ws.db.tx() as c:
                c.execute("INSERT INTO meta(key,value) VALUES('fi:a','1')")
                c.execute("INSERT INTO meta(key,value) VALUES('fi:b','2')")
                raise RuntimeError("boom")
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM meta WHERE key IN ('fi:a','fi:b')").fetchone()["n"], 0)


class ForgedReportTests(VepTestCase):
    def test_a_candidate_that_prints_or_writes_a_passing_report_cannot_certify(self):
        # The candidate's tests all fail, but the candidate tries to forge success three ways: stdout text, a pre-made report file, exit code 0.
        forged = ("import sys, json, os\n"
                  "print('OK  Ran 2 tests  0 failures'); print(json.dumps({'passed': ['a', 'b'], 'failed': [], 'errors': [], 'skipped': []}))\n"
                  "for p in ('report.json', os.environ.get('TMPDIR', '/tmp') + '/report.json'):\n"
                  "    try: open(p, 'w').write(json.dumps({'passed': ['a'], 'failed': []}))\n"
                  "    except OSError: pass\n"
                  "os._exit(0)\n")  # exit 0 straight from the import, before any real test result exists
        e = self.env()
        cid = e.candidate({"tests/test_forge.py": forged, "arithmetic.py": "def add(a, b):\n    return 0\n"})
        controller.enqueue(e.ws, cid)
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        self.assertNotEqual(out.get("candidate_status"), "CERTIFIED")
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "REJECTED")
        with e.ws.db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM certificates").fetchone()["n"], 0)


class OptionalDependencyTests(unittest.TestCase):
    def run_blocked(self, module: str, block: str) -> subprocess.CompletedProcess:
        code = f"import sys; sys.modules[{block!r}]=None; from {module} import main; sys.exit(main([]))"
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=src_env())

    def test_missing_mcp_extra_fails_clearly_with_exit_2(self):
        r = self.run_blocked("vep.mcp_server", "mcp")
        self.assertEqual(r.returncode, 2); self.assertIn("optional 'mcp' extra", r.stderr); self.assertNotIn("Traceback", r.stderr)

    def test_missing_a2a_extra_fails_clearly_with_exit_2(self):
        r = self.run_blocked("vep.a2a_server", "a2a")
        self.assertEqual(r.returncode, 2); self.assertIn("optional 'a2a' extra", r.stderr); self.assertNotIn("Traceback", r.stderr)

    def test_missing_claude_extra_names_the_extra(self):
        r = subprocess.run([sys.executable, "-c", "import sys; sys.modules['claude_agent_sdk']=None; import vep.agent_sdk"], capture_output=True, text=True, env=src_env())
        self.assertNotEqual(r.returncode, 0); self.assertIn("optional 'claude' extra", r.stderr)

    def test_the_core_cli_works_without_any_optional_extra(self):
        code = "import sys; [sys.modules.__setitem__(m, None) for m in ('mcp','a2a','claude_agent_sdk','starlette','uvicorn')]; from vep.cli import main; sys.exit(main(['version','--json']))"
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=src_env())
        self.assertEqual(r.returncode, 0, r.stderr)


class LostResponseAndCapabilityTests(A2ABase):
    def test_a_lost_http_response_is_safely_retried_with_the_same_message_id(self):
        url = self.start("read,register,evaluate", True)
        obj = self.objective()
        (self.root / "feature.py").write_text("def twice(x):\n    return 2 * x\n")
        body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": json.loads(__import__("google.protobuf.json_format", fromlist=["x"]).MessageToJson(
            data_msg({"skill": "vep.verify_change", "objective_id": obj}, "retry-me-1")))}}
        try:  # the caller gives up before reading the response: the connection is dropped mid-request
            httpx.post(url + "/a2a", headers=self.headers(), json=body, timeout=0.05)
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
        r = httpx.post(url + "/a2a", headers=self.headers(), json=body, timeout=120).json()  # the retry
        self.assertIn("result", r, r)
        self.assertEqual(self.n_candidates(), 1)  # one candidate despite two deliveries
        with Workspace(self.root).db.read() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) n FROM jobs").fetchone()["n"], 1)

    def test_unknown_extensions_and_unknown_fields_are_not_silently_honoured(self):
        url = self.start("read")
        from google.protobuf.json_format import MessageToJson
        msg = json.loads(MessageToJson(data_msg({"skill": "vep.get_status"})))
        h = self.headers(); h["A2A-Extensions"] = "https://example.com/unknown-extension/v1"
        r = httpx.post(url + "/a2a", headers=h, json={"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": msg}}, timeout=30).json()
        self.assertTrue("result" in r or "error" in r)  # defined behaviour, not a crash
        self.assertNotIn("Traceback", json.dumps(r))
        r = httpx.post(url + "/a2a", headers=self.headers(), json={"jsonrpc": "2.0", "id": 2, "method": "SendMessage",
                                                                   "params": {"message": msg, "grantAuthority": "export", "verdict": "CERTIFIED"}}, timeout=30).json()
        self.assertEqual(self.n_candidates(), 0)  # and no field of the request can raise authority or inject a verdict
        self.assertNotIn("CERTIFIED", json.dumps(r.get("result", {})))


class CoverageMapTests(unittest.TestCase):
    def test_every_test_named_in_the_fault_injection_map_exists(self):
        text = (ROOT / "docs" / "FAULT_INJECTION.md").read_text()
        refs = re.findall(r"`(tests/test_\w+\.py)::(?:\w+::)?(test_\w+)`", text)
        self.assertGreaterEqual(len(refs), 30)
        missing = [f"{f}::{t}" for f, t in refs if not re.search(rf"def {t}\b", (ROOT / f).read_text())]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
