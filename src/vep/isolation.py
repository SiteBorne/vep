"""Optional Docker + gVisor isolation adapter. Fails closed; never falls back to host execution.

STATUS: plan construction and the probe are exercised by tests. Actual container execution has
NOT been exercised in this build (no daemon/runsc available) and is therefore UNVERIFIED.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .errors import IsolationUnavailable, SchemaError

UNVERIFIED = "ISOLATION_UNVERIFIED"
RUNTIME_PRESENT = "ISOLATION_RUNTIME_PRESENT"
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/\-]*(:[A-Za-z0-9._\-]+)?@sha256:[0-9a-f]{64}$")


@dataclass
class ProbeResult:
    status: str
    reasons: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"status": self.status, "reasons": self.reasons, "detail": self.detail,
                "note": "RUNTIME_PRESENT means a gVisor runtime is registered; escape resistance is NOT tested."}


def _run(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL)


def probe(image: str | None = None) -> ProbeResult:
    """Offline probe: inspects local Docker only. Never pulls images or contacts a registry."""
    docker = shutil.which("docker")
    if not docker:
        return ProbeResult(UNVERIFIED, ["docker executable not found"])
    try:
        info = _run([docker, "info", "--format", "{{json .Runtimes}}"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ProbeResult(UNVERIFIED, [f"docker info failed: {exc.__class__.__name__}"])
    if info.returncode != 0:
        return ProbeResult(UNVERIFIED, ["docker daemon unreachable: " + info.stderr.strip()[:200]])
    try:
        runtimes = json.loads(info.stdout.strip() or "null") or {}
    except json.JSONDecodeError:
        return ProbeResult(UNVERIFIED, ["unparseable docker runtime listing"])
    if "runsc" not in runtimes:
        return ProbeResult(UNVERIFIED, ["gVisor runtime 'runsc' is not registered with Docker"],
                           {"runtimes": sorted(runtimes)})
    if image is not None:
        if not IMAGE_RE.match(image):
            return ProbeResult(UNVERIFIED, ["image is not digest-pinned"])
        ins = _run([docker, "image", "inspect", image])
        if ins.returncode != 0:
            return ProbeResult(UNVERIFIED, ["pinned image is not present locally (VEP never pulls)"])
    return ProbeResult(RUNTIME_PRESENT, [], {"runtimes": sorted(runtimes)})


def build_plan(image: str, source_dir: str, command: list[str], *, cpus: str = "1", memory: str = "512m",
               pids: int = 128, tmpfs_size: str = "64m", uid_gid: str = "65534:65534") -> list[str]:
    """Docker argv for a locked-down offline run. Source is mounted read-only; no VEP state or keys."""
    if not IMAGE_RE.match(image):
        raise SchemaError("image must be digest-pinned (name@sha256:<64 hex>)")
    if not command or not all(isinstance(c, str) for c in command):
        raise SchemaError("command must be a non-empty argv list")
    if "/.vep" in source_dir or source_dir.endswith(".vep"):
        raise SchemaError("VEP state must never be mounted")
    return ["docker", "run", "--rm", "--pull=never", "--runtime=runsc", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", uid_gid,
            "--cpus", cpus, "--memory", memory, "--memory-swap", memory, "--pids-limit", str(pids),
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={tmpfs_size}",
            "--mount", f"type=bind,source={source_dir},target=/work,readonly",
            "--workdir", "/work", image, *command]


def run_isolated(image: str, source_dir: str, command: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    p = probe(image)
    if p.status != RUNTIME_PRESENT:
        raise IsolationUnavailable(f"{p.status}: {'; '.join(p.reasons)} (no host fallback is ever used)")
    return subprocess.run(build_plan(image, source_dir, command), capture_output=True, text=True,
                          timeout=timeout, check=False, stdin=subprocess.DEVNULL)
