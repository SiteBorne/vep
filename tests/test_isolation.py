import subprocess
import unittest
from unittest import mock

from vep import isolation
from vep.errors import IsolationUnavailable, SchemaError

DIGEST = "a" * 64
IMAGE = f"python@sha256:{DIGEST}"


class IsolationPlanTests(unittest.TestCase):
    def plan(self):
        return isolation.build_plan(IMAGE, "/tmp/src", ["python", "-m", "unittest"])

    def test_plan_contains_every_required_hardening_flag(self):
        p = self.plan()
        for flag in ("--pull=never", "--runtime=runsc", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--pids-limit", "--cpus", "--memory"):
            self.assertIn(flag, p)
        self.assertEqual(p[p.index("--user") + 1], "65534:65534")
        self.assertIn("type=bind,source=/tmp/src,target=/work,readonly", p)
        self.assertIn(IMAGE, p)
        self.assertTrue(any(x.startswith("/tmp:rw,noexec,nosuid") for x in p))

    def test_plan_never_mounts_vep_state_or_privileged(self):
        p = " ".join(self.plan())
        for forbidden in ("--privileged", "--network=host", "docker.sock", ".vep", "--cap-add"):
            self.assertNotIn(forbidden, p)
        with self.assertRaises(SchemaError):
            isolation.build_plan(IMAGE, "/work/proj/.vep", ["x"])

    def test_image_must_be_digest_pinned(self):
        for bad in ("python:3.12", "python", "python@sha256:abc", "python@sha256:" + "G" * 64, "latest"):
            with self.assertRaises(SchemaError, msg=bad):
                isolation.build_plan(bad, "/s", ["x"])
        with self.assertRaises(SchemaError):
            isolation.build_plan(IMAGE, "/s", [])


class IsolationProbeTests(unittest.TestCase):
    def test_probe_without_docker_reports_unverified(self):
        with mock.patch("shutil.which", return_value=None):
            r = isolation.probe()
        self.assertEqual(r.status, isolation.UNVERIFIED)
        self.assertIn("not found", r.reasons[0])

    def test_probe_with_unreachable_daemon_reports_unverified(self):
        cp = subprocess.CompletedProcess([], 1, "", "Cannot connect to the Docker daemon")
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), mock.patch.object(isolation, "_run", return_value=cp):
            r = isolation.probe()
        self.assertEqual(r.status, isolation.UNVERIFIED)

    def test_probe_without_gvisor_runtime_reports_unverified(self):
        cp = subprocess.CompletedProcess([], 0, '{"runc":{"path":"runc"}}', "")
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), mock.patch.object(isolation, "_run", return_value=cp):
            r = isolation.probe()
        self.assertEqual(r.status, isolation.UNVERIFIED)
        self.assertIn("runsc", r.reasons[0])

    def test_probe_requires_local_pinned_image_and_never_pulls(self):
        calls = []

        def fake(argv, timeout=15):
            calls.append(argv)
            if argv[1] == "info":
                return subprocess.CompletedProcess(argv, 0, '{"runsc":{"path":"runsc"}}', "")
            return subprocess.CompletedProcess(argv, 1, "", "No such image")
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), mock.patch.object(isolation, "_run", side_effect=fake):
            r = isolation.probe(IMAGE)
            self.assertEqual(r.status, isolation.UNVERIFIED)
            self.assertEqual(isolation.probe("python:latest").status, isolation.UNVERIFIED)
        self.assertFalse(any("pull" in a for c in calls for a in c))

    def test_runtime_present_is_not_an_escape_resistance_claim(self):
        def fake(argv, timeout=15):
            return subprocess.CompletedProcess(argv, 0, '{"runsc":{}}' if argv[1] == "info" else "", "")
        with mock.patch("shutil.which", return_value="/usr/bin/docker"), mock.patch.object(isolation, "_run", side_effect=fake):
            d = isolation.probe(IMAGE).to_dict()
        self.assertEqual(d["status"], isolation.RUNTIME_PRESENT)
        self.assertIn("NOT tested", d["note"])

    def test_run_isolated_fails_closed_without_host_fallback(self):
        with mock.patch.object(isolation, "probe", return_value=isolation.ProbeResult(isolation.UNVERIFIED, ["no daemon"])), \
                mock.patch("subprocess.run", side_effect=AssertionError("must not execute anything")):
            with self.assertRaises(IsolationUnavailable):
                isolation.run_isolated(IMAGE, "/tmp/s", ["python", "-c", "print(1)"])

    def test_real_probe_on_this_host_is_honest(self):
        r = isolation.probe()
        self.assertIn(r.status, (isolation.UNVERIFIED, isolation.RUNTIME_PRESENT))
        if r.status == isolation.UNVERIFIED:
            self.assertTrue(r.reasons)


if __name__ == "__main__":
    unittest.main()
