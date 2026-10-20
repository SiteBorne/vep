"""Environment probes for the paired benchmark: macOS (original behaviour) and Linux (hosted runners).

Pure parsing functions are separated from I/O so they can be unit-tested with captured /proc contents.
Nothing here affects what is measured; it only records the environment.
"""
from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
import time


# ---------------------------------------------------------------- Linux parsing (pure)
def parse_proc_stat_cpu(line: str) -> tuple[int, int]:
    """Return (idle_jiffies, total_jiffies) from the aggregate `cpu` line of /proc/stat.

    idle = idle + iowait; total = user+nice+system+idle+iowait+irq+softirq+steal (guest time is already inside user)."""
    f = [int(x) for x in line.split()[1:]]
    f += [0] * (8 - len(f))
    return f[3] + f[4], sum(f[:8])


def idle_percent(a: tuple[int, int], b: tuple[int, int]) -> float | None:
    d_idle, d_total = b[0] - a[0], b[1] - a[1]
    return None if d_total <= 0 else round(100.0 * d_idle / d_total, 2)


def parse_meminfo(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def parse_cpu_model(cpuinfo: str) -> str | None:
    for line in cpuinfo.splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v.strip().strip('"')
    return out


def _read(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


# ---------------------------------------------------------------- probes (I/O)
def cpu_idle_pct(interval: float = 2.0) -> float | None:
    """CPU idle percentage over a short sampling window (system-wide)."""
    if sys.platform == "darwin":
        r = subprocess.run(["top", "-l", "2", "-n", "0", "-s", str(int(interval))], capture_output=True, text=True)
        m = re.findall(r"CPU usage:.*?([\d.]+)% idle", r.stdout)
        return float(m[-1]) if m else None
    first = _read("/proc/stat").splitlines()
    if not first:
        return None
    a = parse_proc_stat_cpu(first[0])
    time.sleep(interval)
    b = parse_proc_stat_cpu(_read("/proc/stat").splitlines()[0])
    return idle_percent(a, b)


def env_probe() -> dict:
    out = {"load_avg_1m": round(os.getloadavg()[0], 2), "cpu_idle_pct": cpu_idle_pct()}
    if sys.platform != "darwin":
        mem = parse_meminfo(_read("/proc/meminfo"))
        out["mem_available_mb"] = round(mem.get("MemAvailable", 0) / 1024, 1)
    return out


def host_info() -> dict:
    """Static description of the machine. Keys `power` (list) and `swap` (str) keep their original meaning for the report renderer."""
    info = {"platform": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(), "python": platform.python_version(),
            "system": platform.system(), "kernel": platform.release()}
    if sys.platform == "darwin":
        info["power"] = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout.splitlines()[:1]
        info["swap"] = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True).stdout.strip()
        mem = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout.strip()
        info["mem_total_mb"] = round(int(mem) / 1048576) if mem.isdigit() else None
        info["cpu_model"] = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True).stdout.strip() or None
        return info
    mem = parse_meminfo(_read("/proc/meminfo"))
    info["mem_total_mb"] = round(mem.get("MemTotal", 0) / 1024, 1)
    info["mem_available_mb_at_probe"] = round(mem.get("MemAvailable", 0) / 1024, 1)
    info["swap"] = f"total = {mem.get('SwapTotal', 0) // 1024}M free = {mem.get('SwapFree', 0) // 1024}M"
    info["cpu_model"] = parse_cpu_model(_read("/proc/cpuinfo"))
    info["os_release"] = {k: v for k, v in parse_os_release(_read("/etc/os-release")).items() if k in ("NAME", "VERSION", "VERSION_ID", "PRETTY_NAME")}
    info["power"] = ["not applicable (virtual machine)"]
    info["runner"] = {k: os.environ.get(k) for k in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                                                  "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_WORKFLOW", "GITHUB_REF") if os.environ.get(k)}
    return info


if __name__ == "__main__":
    import json
    print(json.dumps({"host": host_info(), "probe": env_probe()}, indent=1))
