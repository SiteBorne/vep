#!/usr/bin/env python3
"""Offline stand-in for the `claude` CLI used ONLY by tests/test_claude_live_harness.py. It performs the VEP steps itself through the vep CLI and prints
a stream-json transcript shaped like the real one (as documented), so the harness's classification can be tested without any model call.
It is not evidence of anything about Claude Code."""
import json
import os
import subprocess
import sys
import time

mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")
py = os.environ["FAKE_PY"]
if "--version" in sys.argv:
    print("0.0.0 (fake-claude for offline tests)"); sys.exit(0)

def vep(*a):
    r = subprocess.run([py, "-m", "vep.cli", *a, "--json"], capture_output=True, text=True)
    return json.loads(r.stdout) if r.stdout.strip() else {}

def emit(o):
    print(json.dumps(o), flush=True)

server_status = "failed" if mode == "mcp_not_connected" else "connected"
tools = [] if mode == "mcp_not_connected" else ["mcp__vep__vep_status", "mcp__vep__vep_evaluate", "Skill"]
emit({"type": "system", "subtype": "init", "mcp_servers": [{"name": "vep", "status": server_status}], "tools": tools,
      "skills": [] if mode == "no_skill" else ["vep"]})
n = 0
def call(tool, inp, text, err=False):
    global n
    n += 1
    tid = f"toolu_{n}"
    emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": tid, "name": tool, "input": inp}]}})
    emit({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tid, "content": text, "is_error": err}]}})

def register_grandchild():
    """Record our pid and a grandchild's before doing anything else, so the test can prove an active kill of the whole process group."""
    child = subprocess.Popen(["sleep", "300"])
    open(os.environ["FAKE_PIDFILE"], "w").write(json.dumps([os.getpid(), child.pid]))

def linger():
    time.sleep(300)

if mode in ("hang", "too_many_calls"):
    register_grandchild()
if mode == "hang":
    linger()
if mode == "too_many_calls":
    for i in range(60):
        call("mcp__vep__vep_status", {}, "{}")
    linger()
elif mode == "fabricated":
    fake = lambda p: p + "-" + "ab" * 32
    call("mcp__vep__vep_status", {}, "{}")
    call("mcp__vep__vep_candidate_register", {"objective_id": "x"}, json.dumps({"candidate_id": fake("cand")}))
    call("mcp__vep__vep_evaluate", {"candidate_id": fake("cand")}, "{}")
    call("mcp__vep__vep_job_status", {}, json.dumps({"result": {"candidate_status": "CERTIFIED", "evidence_id": fake("evd"), "certificate_id": fake("cert")}}))
elif mode not in ("no_tools", "mcp_not_connected", "fabricated"):
    if mode != "no_skill":
        call("Skill", {"skill": "vep"}, "loaded")
    call("mcp__vep__vep_status", {}, "{}")
    o = vep("objective", "create", "--title", "live e2e", "--budget", "1.00")
    call("mcp__vep__vep_objective_create", {"title": "live e2e"}, json.dumps(o))
    body = "def double(x):\n    return 2 * x\n\n\ndef triple(x):\n    return %s * x\n" % ("2" if mode == "wrong_change" else "3")
    open("feature.py", "w").write(body)
    c = vep("candidate", "create", "--objective", o.get("objective_id") or o.get("id") or "", "--author", "fake")
    cand = c.get("candidate_id") or c.get("id")
    call("mcp__vep__vep_candidate_register", {"objective_id": "x"}, json.dumps({"candidate_id": cand}))
    run = vep("run", "--candidate", cand, "--trusted-local-execution")
    r = run.get("run", {})
    call("mcp__vep__vep_evaluate", {"candidate_id": cand}, json.dumps({"job_id": run.get("job", {}).get("id")}))
    shown = {"candidate_id": cand, "candidate_status": r.get("candidate_status")}
    if mode != "hidden_ids":
        shown.update(evidence_id=r.get("evidence_id"), certificate_id=r.get("certificate_id"))
    call("mcp__vep__vep_job_status", {"candidate_id": cand}, json.dumps({"result": shown, "api_key": "sk-abcdefghijklmnop1234"}))
emit({"type": "result", "is_error": False, "total_cost_usd": 0.0, "num_turns": 3})
