"""Opt-in switches for measured performance experiments (benchmarks/analysis). Each flag guards ONE optimization whose adoption is decided by a
preregistered rule; the production default of a flag is changed only when the experiment passes. Environment override: VEP_PERF=flag1,flag2 (or `none`).

staging_fast      Experiment A1: create each directory once and each staged file with O_EXCL|O_NOFOLLOW at its final mode (no per-file mkdir/chmod by path)
staging_clone     Experiment A2: copy-on-write clone (macOS clonefile, Linux FICLONE) of a CAS blob instead of reading it; falls back to a normal write; never a hard link
verified_handoff  Experiment B: one verifying read of every blob per evaluation; the verified bytes (bounded in memory) are reused for staging
"""
from __future__ import annotations

import os
from collections import defaultdict

DEFAULTS = {"staging_fast": False, "staging_clone": False, "verified_handoff": False}
HANDOFF_CAP_BYTES = 128 * 1024 * 1024


def enabled(name: str) -> bool:
    env = os.environ.get("VEP_PERF")
    if env is not None:
        return name in {x.strip() for x in env.split(",")}
    return DEFAULTS[name]


# Activation counters: did the mechanism actually run, or did the code fall back / bypass it? Process-local; benchmarks read them after a run.
STATS: dict[str, int] = defaultdict(int)


def count(name: str, n: int = 1) -> None:
    STATS[name] += n
