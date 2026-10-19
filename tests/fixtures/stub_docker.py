#!/usr/bin/env python3
"""TEST STUB standing in for the docker CLI. It is NOT a container runtime and proves nothing about
isolation: it returns canned answers so the decision logic of vep.isolation can be exercised offline.
For the evaluator command it runs the protected runner directly on the host, purely to test evidence
plumbing. Behavior is tuned through the JSON file named by STUB_DOCKER_CONFIG."""
import json, os, subprocess, sys, time

cfg = json.load(open(os.environ["STUB_DOCKER_CONFIG"]))
PIN = cfg["pin"]
GOOD_PROBE = {
    "T1_source_readable": {"ok": True, "value": 1}, "T2_source_write": {"ok": False, "error": "OSError"},
    "T3_root_write": {"ok": False, "error": "OSError"}, "T4_key_files": {"ok": True, "value": []},
    "T5_db_files": {"ok": True, "value": []}, "T6_network_connect": {"ok": False, "error": "OSError"},
    "T6_interfaces": {"ok": True, "value": ["lo"]}, "T7_uid": {"ok": True, "value": 65534},
    "T7_cap_eff": {"ok": True, "value": "0000000000000000"}, "T7_no_new_privs": {"ok": True, "value": "1"},
    "T7_setuid_root": {"ok": False, "error": "PermissionError"}, "T7_docker_sock": {"ok": True, "value": False}}
probe = dict(GOOD_PROBE, **cfg.get("probe_overrides", {}))
a = sys.argv[1:]
log = open(cfg["log"], "a"); log.write(json.dumps(a) + "\n"); log.close()
if a[:1] == ["info"]:
    rt = {"runc": {}, **({"runsc": {}} if cfg.get("runsc", True) else {})}
    print(json.dumps({"Runtimes": rt, "SecurityOptions": ["name=seccomp"], "OperatingSystem": "StubOS", "OSType": "linux", "Architecture": "x86_64"}))
elif a[:2] == ["image", "inspect"]:
    img = a[-1]
    if img == PIN and cfg.get("image_present", True):
        print("sha256:" + "d" * 64 + "|" + json.dumps([PIN if cfg.get("digest_ok", True) else "other@sha256:" + "e" * 64]))
    else:
        sys.exit(1)
elif a[:1] == ["rm"] or a[:1] == ["ps"]:
    if a[:1] == ["ps"] and cfg.get("leave_container"):
        print("deadbeef")
elif a[:1] == ["inspect"]:
    print(cfg.get("inspect", "runsc|none|true|false|134217728|64"))
elif a[:1] == ["run"]:
    if "--runtime=runsc-does-not-exist" in a:
        print("docker: unknown runtime", file=sys.stderr); sys.exit(125)
    if "-d" in a:
        print("containerid"); sys.exit(0)
    i = a.index(PIN) if PIN in a else None
    cmd = a[i + 1:] if i is not None else []
    mounts = [x for x in a if x.startswith("type=bind")]
    src = [m.split("source=")[1].split(",")[0] for m in mounts if "target=/work" in m]
    if any("_isolation_probe" in c for c in cmd):
        print("VEP_ISOLATION_PROBE:" + json.dumps(probe)); sys.exit(0)
    if any("bytearray(600" in c for c in cmd):
        sys.exit(cfg.get("oom_rc", 137))
    if any("time.sleep(120)" in c for c in cmd):
        time.sleep(120); sys.exit(0)
    if any("_runner.py" in c for c in cmd):
        runner = [m.split("source=")[1].split(",")[0] for m in mounts if "target=/vep/_runner.py" in m][0]
        c = json.loads(cmd[-1]); c["root"] = src[0]
        r = subprocess.run([sys.executable, "-I", runner, json.dumps(c)], capture_output=True, text=True, cwd=src[0])
        sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); sys.exit(r.returncode)
    print("RAN")
else:
    sys.exit(2)
