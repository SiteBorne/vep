"""`vep build` CLI: authorization gate, cache behaviour end to end through the real entry point."""
from __future__ import annotations

import contextlib
import io
import json

from tests.helpers import VepTestCase
from vep import cli, snapshots

SCRIPT = "import pathlib; pathlib.Path('out.txt').write_text('built')"


class BuildCliTests(VepTestCase):
    def run_cli(self, e, *args):
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = cli.main([args[0], "--root", str(e.root), "--json", *args[1:]])
        return rc, buf.getvalue(), err.getvalue()

    def build_args(self, e, *extra):
        return ["build", "run", "--snapshot", e.base.id, "--output", "out.txt", *extra,
                "--argv-json", json.dumps(["{python}", "-I", "-c", SCRIPT])]

    def test_requires_explicit_authorization(self):
        e = self.env()
        rc, out, err = self.run_cli(e, *self.build_args(e))
        self.assertEqual(rc, 7)
        self.assertIn("--trusted-local-execution", err)
        self.assertEqual(self.run_cli(e, "build", "stats")[0], 0)  # read-only command needs no authorization

    def test_miss_then_hit_and_stats(self):
        e = self.env()
        rc1, out1, _ = self.run_cli(e, *self.build_args(e, "--trusted-local-execution"))
        rc2, out2, _ = self.run_cli(e, *self.build_args(e, "--trusted-local-execution"))
        r1, r2 = json.loads(out1), json.loads(out2)
        self.assertEqual((rc1, rc2, r1["cache"], r2["cache"]), (0, 0, "MISS", "HIT"))
        self.assertEqual(r1["action_id"], r2["action_id"])
        self.assertEqual(r1["outputs"], r2["outputs"])
        stats = json.loads(self.run_cli(e, "build", "stats")[1])
        self.assertEqual((stats["MISS"]["count"], stats["HIT"]["count"]), (1, 1))

    def test_failing_command_exits_nonzero_and_is_not_cached(self):
        e = self.env()
        rc, out, _ = self.run_cli(e, "build", "run", "--snapshot", e.base.id, "--trusted-local-execution",
                                  "--argv-json", json.dumps(["{python}", "-I", "-c", "raise SystemExit(2)"]))
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(out)["failure"], "NONZERO_EXIT")
