"""Agent adapters: allowlist, usage provenance, no self-certification, end-to-end through controller."""
from __future__ import annotations

import http.server
import json
import sys
import threading

from tests.helpers import AUTH, VepTestCase
from vep import agents, candidates, controller
from vep.errors import AuthorizationError

EDIT = "import sys, pathlib\np = pathlib.Path(sys.argv[1]) / 'extra.py'\np.write_text('Y = 2\\n')\n"
FORGE = EDIT + "import os, json\njson.dump({'input_tokens': 1, 'output_tokens': 1}, open(os.environ['VEP_USAGE_FILE'], 'w'))\n"
DELETE_TESTS = "import sys, shutil, pathlib\nshutil.rmtree(pathlib.Path(sys.argv[1]) / 'tests')\n"
SLEEP = "import time\ntime.sleep(30)\n"


class AdapterTests(VepTestCase):
    def adapter(self, e, **scripts):
        allow = {}
        for name, src in scripts.items():
            path = self.tmp / f"{name}.py"
            path.write_text(src)
            allow[name] = {"executable": sys.executable, "args": ["-I", str(path), "{workdir}"]}
        allow["echo"] = {"executable": sys.executable, "args": ["-I", "-c", "print(1)", "{param:x}"]}
        return agents.StructuredSubprocessAdapter("subproc", allow)

    def task(self, e, tool, **params):
        return agents.AgentTask(e.objective.id, e.base.id, e.policy.id, "do it", {"tool": tool, **params}, timeout_s=20)

    def test_agent_change_goes_through_controller_and_certifies(self):
        e = self.env()
        res = agents.run_agent_task(e.ws, self.adapter(e, edit=EDIT), self.task(e, "edit"), "agent-1")
        self.assertEqual((res["status"], res["error_class"]), ("COMPLETED", "NONE"))
        self.assertEqual(res["changes"]["added"], ["extra.py"])
        self.assertEqual(res["usage"]["source"], "locally_measured")
        self.assertEqual(res["input_snapshot_id"], e.base.id)
        cid = res["candidate_id"]
        self.assertEqual(candidates.get_state(e.ws, cid)["status"], "PROPOSED")  # adapter granted nothing
        controller.enqueue(e.ws, cid)
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        self.assertEqual(out["candidate_status"], "CERTIFIED")

    def test_unlisted_tool_and_option_injection_refused(self):
        e = self.env()
        a = self.adapter(e, edit=EDIT)
        r = agents.run_agent_task(e.ws, a, self.task(e, "rm"), "x")
        self.assertEqual((r["status"], r["error_class"], r["candidate_id"]), ("FAILED", "NOT_ALLOWED", None))
        r = agents.run_agent_task(e.ws, a, self.task(e, "echo", x="--version"), "x")
        self.assertEqual(r["error_class"], "NOT_ALLOWED")
        r = agents.run_agent_task(e.ws, a, self.task(e, "echo", x="a\0b"), "x")
        self.assertEqual(r["error_class"], "NOT_ALLOWED")

    def test_relative_executable_rejected_at_construction(self):
        with self.assertRaises(AuthorizationError):
            agents.StructuredSubprocessAdapter("s", {"t": {"executable": "python3", "args": []}})

    def test_forged_usage_is_labelled_caller_supplied(self):
        e = self.env()
        r = agents.run_agent_task(e.ws, self.adapter(e, forge=FORGE), self.task(e, "forge"), "x")
        self.assertEqual(r["usage"]["source"], "locally_measured")
        self.assertEqual(r["usage"]["tool_claimed"]["source"], "caller_supplied")

    def test_timeout_is_classified_and_yields_no_candidate(self):
        e = self.env()
        t = self.task(e, "sleep")
        t.timeout_s = 1
        r = agents.run_agent_task(e.ws, self.adapter(e, sleep=SLEEP), t, "x")
        self.assertEqual((r["error_class"], r["candidate_id"]), ("TIMEOUT", None))

    def test_agent_deleting_tests_cannot_get_certified(self):
        e = self.env()
        r = agents.run_agent_task(e.ws, self.adapter(e, rm=DELETE_TESTS), self.task(e, "rm"), "x")
        self.assertIn("tests/test_arithmetic.py", r["changes"]["removed"])
        controller.enqueue(e.ws, r["candidate_id"])
        out = controller.run_one(e.ws, controller.LocalToolWorker("w", AUTH))
        self.assertNotEqual(out.get("candidate_status"), "CERTIFIED")

    def test_workspace_state_untouched(self):
        e = self.env()
        before = sorted(p.name for p in e.root.iterdir())
        agents.run_agent_task(e.ws, self.adapter(e, edit=EDIT), self.task(e, "edit"), "x")
        self.assertEqual(sorted(p.name for p in e.root.iterdir()), before)


class _Handler(http.server.BaseHTTPRequestHandler):
    reply: dict = {}

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        data = json.dumps(self.reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class OllamaAdapterTests(VepTestCase):
    """Protocol tests against a local STUB server. They do not demonstrate live model integration."""

    def serve(self, reply):
        _Handler.reply = reply
        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_port}"

    def run_it(self, e, url):
        a = agents.OllamaAdapter("stub", url)
        t = agents.AgentTask(e.objective.id, e.base.id, e.policy.id, "add file", {}, timeout_s=10)
        return agents.run_agent_task(e.ws, a, t, "llm")

    def test_provider_usage_and_file_write(self):
        e = self.env()
        url = self.serve({"message": {"content": json.dumps({"files": {"new.py": "Z = 3\n"}})},
                          "prompt_eval_count": 11, "eval_count": 7})
        r = self.run_it(e, url)
        self.assertEqual(r["changes"]["added"], ["new.py"])
        self.assertEqual(r["usage"]["provider"], {"source": "provider_reported", "input_tokens": 11, "output_tokens": 7})
        self.assertIsNotNone(r["candidate_id"])

    def test_path_traversal_and_garbage_rejected(self):
        e = self.env()
        r = self.run_it(e, self.serve({"message": {"content": json.dumps({"files": {"../evil.py": "x"}})}}))
        self.assertEqual((r["error_class"], r["candidate_id"]), ("BAD_OUTPUT", None))
        r = self.run_it(e, self.serve({"message": {"content": "not json"}}))
        self.assertEqual(r["error_class"], "BAD_OUTPUT")

    def test_runtime_unavailable(self):
        e = self.env()
        r = self.run_it(e, "http://127.0.0.1:9")
        self.assertEqual(r["error_class"], "RUNTIME_UNAVAILABLE")


class UsageRecordingTests(VepTestCase):
    def test_provider_and_caller_usage_keep_their_provenance(self):
        from vep import tokens
        e = self.env()
        # runtime-reported usage (stub server)
        _Handler.reply = {"message": {"content": json.dumps({"files": {"n.py": "A = 1\n"}})},
                          "prompt_eval_count": 40, "eval_count": 10}
        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        t = agents.AgentTask(e.objective.id, e.base.id, e.policy.id, "x", {}, timeout_s=10)
        r = agents.run_agent_task(e.ws, agents.OllamaAdapter("stub", f"http://127.0.0.1:{srv.server_port}"), t, "llm")
        out = agents.record_usage(e.ws, r)
        self.assertEqual(out["cost_usd"], "0")
        self.assertFalse(agents.record_usage(e.ws, r)["duplicate"] is False)  # idempotent
        # tool-claimed usage on another candidate
        p = self.tmp / "forge.py"
        p.write_text(FORGE)
        ad = agents.StructuredSubprocessAdapter("sp", {"f": {"executable": sys.executable, "args": ["-I", str(p), "{workdir}"]}})
        r2 = agents.run_agent_task(e.ws, ad, agents.AgentTask(e.objective.id, e.base.id, e.policy.id, "x", {"tool": "f"}), "x")
        agents.record_usage(e.ws, r2)
        rep1, rep2 = tokens.usage_report(e.ws, r["candidate_id"]), tokens.usage_report(e.ws, r2["candidate_id"])
        self.assertEqual(list(rep1["by_source"]), ["provider_reported"])
        self.assertEqual(rep1["by_source"]["provider_reported"]["input_tokens"], 40)
        self.assertEqual(list(rep2["by_source"]), ["caller_supplied"])

    def test_no_usage_means_no_receipt(self):
        e = self.env()
        p = self.tmp / "e.py"
        p.write_text(EDIT)
        ad = agents.StructuredSubprocessAdapter("sp", {"e": {"executable": sys.executable, "args": ["-I", str(p), "{workdir}"]}})
        r = agents.run_agent_task(e.ws, ad, agents.AgentTask(e.objective.id, e.base.id, e.policy.id, "x", {"tool": "e"}), "x")
        self.assertIsNone(agents.record_usage(e.ws, r))
