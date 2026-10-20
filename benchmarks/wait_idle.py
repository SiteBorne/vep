"""Bounded idle check before a benchmark workload. It can only WAIT for the declared criterion; it can never relax it.

    python benchmarks/wait_idle.py --timeout 900 --interval 10 --out idle-check.json

Succeeds (exit 0) as soon as the 1-minute load average is strictly below the declared limit (2.0). If that does not happen
within the timeout it exits 3 and the caller must report the environment as invalid (and not run the workload). Every sample is
recorded so the attempt is auditable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import envinfo  # noqa: E402

DECLARED_MAX_LOAD = 2.0  # the launch gate's criterion for load_avg_1m_at_start; not configurable upwards


def evaluate(samples: list[dict], max_load: float = DECLARED_MAX_LOAD) -> dict:
    ok = [s for s in samples if s["load_avg_1m"] < max_load]
    return {"criterion": f"load_avg_1m < {max_load}", "achieved": bool(ok), "first_ok_sample": ok[0] if ok else None,
            "samples": len(samples), "min_load_avg_1m": min((s["load_avg_1m"] for s in samples), default=None)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-load", type=float, default=DECLARED_MAX_LOAD)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--interval", type=int, default=10)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    a = ap.parse_args(argv)
    if a.max_load > DECLARED_MAX_LOAD:
        print(f"refusing: the declared criterion is load < {DECLARED_MAX_LOAD}; it cannot be raised", file=sys.stderr)
        return 2
    samples, t0 = [], time.monotonic()
    while True:
        s = {"t_s": round(time.monotonic() - t0, 1), "load_avg_1m": round(os.getloadavg()[0], 2), "cpu_idle_pct": envinfo.cpu_idle_pct(1.0)}
        samples.append(s)
        if s["load_avg_1m"] < a.max_load or time.monotonic() - t0 >= a.timeout:
            break
        time.sleep(a.interval)
    result = {"label": a.label, "timeout_s": a.timeout, "interval_s": a.interval, "result": evaluate(samples, a.max_load), "samples_detail": samples}
    Path(a.out).write_text(json.dumps(result, indent=1))
    print(json.dumps(result["result"]))
    return 0 if result["result"]["achieved"] else 3


if __name__ == "__main__":
    sys.exit(main())
