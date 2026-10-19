"""Runs INSIDE the isolation container (stdlib only). Prints one JSON object describing what the
sandbox actually permits. Each check records an observation; the host decides PASS/FAIL."""
import json
import os
import socket
import sys


def attempt(fn):
    try:
        return {"ok": True, "value": fn()}
    except BaseException as exc:  # observation, not control flow
        return {"ok": False, "error": exc.__class__.__name__}


def status_field(name):
    with open("/proc/self/status") as fh:
        for line in fh:
            if line.startswith(name + ":"):
                return line.split(":", 1)[1].strip()


def walk_for(names, roots=("/", )):
    found = []
    for root in roots:
        for dp, dn, fn in os.walk(root, followlinks=False):
            if dp.startswith(("/proc", "/sys", "/dev")):
                dn[:] = []
                continue
            for f in fn:
                if f in names:
                    found.append(os.path.join(dp, f))
            if len(found) > 5:
                return found
    return found


def main():
    src = sys.argv[1]
    out = {}
    out["T1_source_readable"] = attempt(lambda: len(os.listdir(src)))
    out["T2_source_write"] = attempt(lambda: open(os.path.join(src, ".vep_probe_write"), "w").write("x"))
    out["T3_root_write"] = attempt(lambda: open("/vep_probe_root_write", "w").write("x"))
    out["T4_key_files"] = attempt(lambda: walk_for({"signing.pem", "id_rsa", "id_ed25519"}))
    out["T5_db_files"] = attempt(lambda: walk_for({"vep.db", "vep.db-wal"}))

    def net():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect(("1.1.1.1", 53))
        finally:
            s.close()
    out["T6_network_connect"] = attempt(net)
    out["T6_interfaces"] = attempt(lambda: sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else [])
    out["T7_uid"] = attempt(lambda: os.getuid())
    out["T7_cap_eff"] = attempt(lambda: status_field("CapEff"))
    out["T7_no_new_privs"] = attempt(lambda: status_field("NoNewPrivs"))
    out["T7_setuid_root"] = attempt(lambda: os.setuid(0))
    out["T7_docker_sock"] = attempt(lambda: os.path.exists("/var/run/docker.sock"))
    print("VEP_ISOLATION_PROBE:" + json.dumps(out, sort_keys=True))


main()
