"""Optional Docker + gVisor isolation adapter. Fails closed; never falls back to host execution.

STATUS: capability detection, plan construction, the verification matrix (T1-T12) and the isolated
evaluator path are implemented. Against a REAL runtime they have not been exercised on the development
host (macOS, Docker daemon not running, no runsc), so the result there is ISOLATION_UNVERIFIED. Tests of
the decision logic use a clearly-labeled stub `docker` executable and prove nothing about real isolation.
"""
from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import uuid
from pathlib import Path
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


_MOUNT_SAFE = re.compile(r"^/[A-Za-z0-9_./+@:-]+$")


def _safe_mount_path(path: str, what: str) -> str:
    """Docker's --mount value is comma/equals separated: a crafted path could add options (rw, other targets)."""
    if not _MOUNT_SAFE.match(path) or ".." in path.split("/"):
        raise SchemaError(f"{what} path contains characters that are unsafe in a docker --mount value: {path!r}")
    return path


def build_plan(image: str, source_dir: str, command: list[str], *, cpus: str = "1", memory: str = "512m",
               pids: int = 128, tmpfs_size: str = "64m", uid_gid: str = "65534:65534") -> list[str]:
    """Docker argv for a locked-down offline run. Source is mounted read-only; no VEP state or keys."""
    if not IMAGE_RE.match(image):
        raise SchemaError("image must be digest-pinned (name@sha256:<64 hex>)")
    if not command or not all(isinstance(c, str) for c in command):
        raise SchemaError("command must be a non-empty argv list")
    _safe_mount_path(source_dir, "source")
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


# ------------------------------------------------------------------ capability detection
def _norm_repo(ref: str) -> str:
    repo = ref.split("@", 1)[0]
    if ":" in repo.rsplit("/", 1)[-1]:  # drop a :tag (never a registry port, which precedes a slash)
        repo = repo.rsplit(":", 1)[0]
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/", "library/"):
        if repo.startswith(prefix):
            return repo[len(prefix):]
    return repo


def pin_matches(image: str, repo_digests: list[str], image_id: str) -> bool:
    """Does the local image carry exactly the pinned content digest?

    Docker lists RepoDigests as `name@sha256:...` WITHOUT the tag, so a pin written as `name:tag@sha256:...`
    must be compared on repository name and digest, never as a whole string. The tag is advisory; the digest decides.
    """
    want_digest = image.split("@sha256:", 1)[1]
    if image_id == "sha256:" + want_digest:
        return True
    want_repo = _norm_repo(image)
    return any(rd.partition("@sha256:")[2] == want_digest and _norm_repo(rd) == want_repo for rd in repo_digests)


def detect_capabilities(image: str | None = None, docker: str | None = None) -> dict:
    """Report what the local environment can and cannot do. Observation only; never pulls or starts anything."""
    docker = docker or shutil.which("docker")
    caps: dict = {"os": platform.system(), "os_release": platform.release(), "machine": platform.machine(),
                  "docker_cli": docker, "daemon": None, "runtimes": [], "runsc_registered": False,
                  "security_options": [], "server_os": None, "image": None, "image_present": False,
                  "image_id": None, "image_pinned_digest_ok": None, "readonly_rootfs_supported": None,
                  "notes": []}
    if platform.system() == "Darwin":
        caps["notes"].append("macOS: containers run in a Linux VM; runsc must be registered in THAT daemon. "
                             "Docker Desktop does not ship gVisor.")
    if not docker:
        caps["notes"].append("docker CLI not found")
        return caps
    try:
        info = _run([docker, "info", "--format", "{{json .}}"], timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        caps["notes"].append(f"docker info failed: {exc.__class__.__name__}")
        return caps
    if info.returncode != 0:
        caps["daemon"] = False
        caps["notes"].append("docker daemon unreachable: " + info.stderr.strip()[:160])
        return caps
    caps["daemon"] = True
    try:
        doc = json.loads(info.stdout)
    except json.JSONDecodeError:
        caps["notes"].append("unparseable docker info")
        return caps
    caps["runtimes"] = sorted((doc.get("Runtimes") or {}).keys())
    caps["runsc_registered"] = "runsc" in caps["runtimes"]
    caps["security_options"] = doc.get("SecurityOptions") or []
    caps["server_os"] = f"{doc.get('OperatingSystem')} / {doc.get('OSType')} / {doc.get('Architecture')}"
    caps["readonly_rootfs_supported"] = doc.get("OSType") == "linux"
    if image:
        caps["image"] = image
        if not IMAGE_RE.match(image):
            caps["notes"].append("image reference is not digest-pinned")
        else:
            ins = _run([docker, "image", "inspect", "--format", "{{.Id}}|{{json .RepoDigests}}", image])
            if ins.returncode == 0:
                caps["image_present"] = True
                iid, _, rd = ins.stdout.strip().partition("|")
                caps["image_id"] = iid
                caps["image_pinned_digest_ok"] = pin_matches(image, json.loads(rd or "[]") or [], iid)
            else:
                caps["notes"].append("pinned image not present locally (VEP never pulls)")
    return caps


# ------------------------------------------------------------------ verification matrix T1-T12
MATRIX = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8", "T9", "T10", "T11", "T12"]
NAMES = {"T1": "source readable", "T2": "source mount not writable", "T3": "root filesystem read-only",
         "T4": "signing key absent", "T5": "VEP database absent", "T6": "external networking denied",
         "T7": "privileged operations denied", "T8": "resource limits enforced", "T9": "timeout terminates work",
         "T10": "runtime errors fail closed", "T11": "image substitution detected", "T12": "runtime identity recorded"}
LIMITS = {"cpus": "1", "memory": "128m", "pids": 64, "tmpfs": "16m", "timeout_s": 20}
T9_TIMEOUT_S = 4
PROBE_PATH = Path(__file__).with_name("_isolation_probe.py")
RUNNER_PATH = Path(__file__).with_name("_runner.py")


def _plan(image, source, mounts_ro, command, name, runtime="runsc", limits=LIMITS, extra=()):
    argv = build_plan(image, source, command, cpus=limits["cpus"], memory=limits["memory"], pids=limits["pids"],
                      tmpfs_size=limits["tmpfs"])
    i = argv.index("--runtime=runsc")
    argv[i] = f"--runtime={runtime}"
    argv.remove("--rm")
    argv[2:2] = ["--name", name, "--label", "vep=isolation", "--ipc=none"]  # keep `docker run` first
    idx = argv.index(image)
    for host, ctr in mounts_ro:
        _safe_mount_path(host, "mount source"); _safe_mount_path(ctr, "mount target")
        argv[idx:idx] = ["--mount", f"type=bind,source={host},target={ctr},readonly"]
        idx += 2
    for e in extra:
        argv[idx:idx] = [e]; idx += 1
    return argv


def _docker_run(docker, argv, timeout):
    """Run a plan; ALWAYS force-remove the named container afterwards. Returns (rc|None, stdout, stderr, timed_out)."""
    name = argv[argv.index("--name") + 1]
    argv = [docker] + argv[1:]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr, False
    except subprocess.TimeoutExpired:
        return None, "", "", True
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True, text=True, check=False, timeout=30,
                       stdin=subprocess.DEVNULL)


def verify_runtime(image: str, source_dir: str | None = None, docker: str | None = None) -> dict:
    """Execute the offline matrix T1-T12 against the local runtime. Returns an attestation dict.

    status is ISOLATED_VERIFIED only if every test is PASS from an observation made in this call.
    Anything else is ISOLATION_UNVERIFIED; tests that could not run are NOT_RUN (never PASS).
    """
    import tempfile
    docker = docker or shutil.which("docker")
    results = {t: {"name": NAMES[t], "status": "NOT_RUN", "observation": None} for t in MATRIX}
    caps = detect_capabilities(image, docker)
    att = {"attestation_version": 1, "image": image, "limits": LIMITS, "capabilities": caps,
           "results": results, "status": UNVERIFIED, "reasons": [], "runtime_identity": None}
    pre = []
    if not docker: pre.append("docker CLI missing")
    if caps.get("daemon") is not True: pre.append("docker daemon unavailable")
    if not caps.get("runsc_registered"): pre.append("runsc runtime not registered")
    if not IMAGE_RE.match(image or ""): pre.append("image not digest-pinned")
    if not caps.get("image_present"): pre.append("pinned image not present locally")
    if caps.get("image_pinned_digest_ok") is not True: pre.append("local image does not match the pinned digest (T11 precondition)")
    if pre:
        att["reasons"] = pre
        return att
    tmp = Path(tempfile.mkdtemp(prefix="vep-isoverify-"))
    try:
        src = Path(source_dir) if source_dir else tmp / "src"
        src.mkdir(exist_ok=True)
        if not source_dir:
            (src / "hello.txt").write_text("hello")
        mounts = [(str(PROBE_PATH), "/vep/_isolation_probe.py")]
        pname = f"vep-iso-{uuid.uuid4().hex[:12]}"
        plan = _plan(image, str(src), mounts, ["python", "-I", "/vep/_isolation_probe.py", "/work"], pname)
        rc, out, err, to = _docker_run(docker, plan, LIMITS["timeout_s"])
        probe = None
        for line in out.splitlines():
            if line.startswith("VEP_ISOLATION_PROBE:"):
                probe = json.loads(line.split(":", 1)[1])
        def mark(t, ok, obs):
            results[t]["status"] = "PASS" if ok else "FAIL"; results[t]["observation"] = obs
        if rc != 0 or probe is None:
            for t in ("T1", "T2", "T3", "T4", "T5", "T6", "T7"):
                mark(t, False, f"probe did not run: rc={rc} timed_out={to} stderr={err.strip()[:160]}")
        else:
            P = probe
            mark("T1", P["T1_source_readable"]["ok"], P["T1_source_readable"])
            mark("T2", not P["T2_source_write"]["ok"], P["T2_source_write"])
            mark("T3", not P["T3_root_write"]["ok"], P["T3_root_write"])
            mark("T4", P["T4_key_files"]["ok"] and P["T4_key_files"]["value"] == [], P["T4_key_files"])
            mark("T5", P["T5_db_files"]["ok"] and P["T5_db_files"]["value"] == [], P["T5_db_files"])
            ifaces = P["T6_interfaces"].get("value") or []
            mark("T6", not P["T6_network_connect"]["ok"] and all(i == "lo" for i in ifaces), {
                "connect": P["T6_network_connect"], "interfaces": ifaces})
            mark("T7", P["T7_uid"].get("value") not in (0, None) and not P["T7_setuid_root"]["ok"]
                 and P["T7_cap_eff"].get("value") in ("0000000000000000", "0")
                 and P["T7_no_new_privs"].get("value") == "1" and P["T7_docker_sock"].get("value") is False,
                 {k: P[k] for k in ("T7_uid", "T7_cap_eff", "T7_no_new_privs", "T7_setuid_root", "T7_docker_sock")})
        # T8: memory limit enforced behaviorally and via HostConfig
        name8 = f"vep-iso-{uuid.uuid4().hex[:12]}"
        plan8 = _plan(image, str(src), [], ["python", "-c", "x=bytearray(600*1024*1024); print('ALLOCATED')"], name8)
        rc8, out8, err8, to8 = _docker_run(docker, plan8, LIMITS["timeout_s"])
        mark("T8", (rc8 not in (0, None)) and "ALLOCATED" not in out8, {"rc": rc8, "timed_out": to8, "limit": LIMITS["memory"]})
        # T9: timeout terminates work and leaves no container
        name9 = f"vep-iso-{uuid.uuid4().hex[:12]}"
        plan9 = _plan(image, str(src), [], ["python", "-c", "import time; time.sleep(120)"], name9)
        rc9, _, _, to9 = _docker_run(docker, plan9, T9_TIMEOUT_S)
        left = subprocess.run([docker, "ps", "-aq", "--filter", f"name={name9}"], capture_output=True, text=True, check=False)
        mark("T9", to9 and left.returncode == 0 and left.stdout.strip() == "", {"timed_out": to9, "leftover": left.stdout.strip()})
        # T10: wrong runtime must fail closed (docker refuses; nothing runs elsewhere)
        name10 = f"vep-iso-{uuid.uuid4().hex[:12]}"
        plan10 = _plan(image, str(src), [], ["python", "-c", "print('RAN')"], name10, runtime="runsc-does-not-exist")
        rc10, out10, _, _ = _docker_run(docker, plan10, LIMITS["timeout_s"])
        mark("T10", rc10 not in (0, None) and "RAN" not in out10, {"rc": rc10})
        # T11: a substituted image (different digest) must not match the pin
        fake = image[:-1] + ("0" if image[-1] != "0" else "1")
        chk = _run([docker, "image", "inspect", "--format", "{{json .RepoDigests}}", fake])
        mark("T11", caps["image_pinned_digest_ok"] is True and chk.returncode != 0,
             {"pinned_ok": caps["image_pinned_digest_ok"], "substituted_image_resolves": chk.returncode == 0})
        # T12: record the runtime actually used by a container we started
        name12 = f"vep-iso-{uuid.uuid4().hex[:12]}"
        plan12 = _plan(image, str(src), [], ["python", "-c", "print('ok')"], name12)
        run12 = subprocess.run([docker] + plan12[1:2] + ["-d"] + plan12[2:], capture_output=True, text=True, check=False)
        try:
            ins = _run([docker, "inspect", "--format", "{{.HostConfig.Runtime}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.HostConfig.Memory}}|{{.HostConfig.PidsLimit}}", name12])
        finally:
            subprocess.run([docker, "rm", "-f", name12], capture_output=True, check=False)
        parts = ins.stdout.strip().split("|") if ins.returncode == 0 else []
        ok12 = len(parts) == 6 and parts[0] == "runsc" and parts[1] == "none" and parts[2] == "true" and parts[3] == "false" \
            and int(parts[5] or 0) == LIMITS["pids"] and int(parts[4] or 0) == 128 * 1024 * 1024
        if ok12:
            att["runtime_identity"] = {"runtime": parts[0], "network_mode": parts[1], "readonly_rootfs": True,
                                       "privileged": False, "memory_bytes": int(parts[4]), "pids_limit": int(parts[5]),
                                       "corroboration": "docker-inspect-only", "image_id": caps["image_id"],
                                       "server": caps["server_os"]}
        mark("T12", ok12, {"inspect": parts, "start_rc": run12.returncode})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if all(r["status"] == "PASS" for r in results.values()):
        att["status"] = "ISOLATED_VERIFIED"
    else:
        att["reasons"] = [f"{t} {r['name']}: {r['status']}" for t, r in results.items() if r["status"] != "PASS"]
    return att


def attestation_is_current(att: dict, image: str, docker: str | None = None) -> tuple[bool, str]:
    """An attestation authorizes isolated evaluation only for the same image and an unchanged runtime."""
    if att.get("status") != "ISOLATED_VERIFIED" or att.get("image") != image:
        return False, "attestation is not an ISOLATED_VERIFIED result for this image"
    caps = detect_capabilities(image, docker)
    now = att.get("capabilities", {})
    if not (caps["daemon"] and caps["runsc_registered"] and caps["image_pinned_digest_ok"]):
        return False, "runtime or image no longer matches"
    if caps["image_id"] != now.get("image_id"):
        return False, "image id changed since verification"
    return True, "ok"
