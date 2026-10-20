"""Build actions: identity, cache hit/miss accounting, corruption, nondeterminism, invalidation."""
from __future__ import annotations

import os

from tests.helpers import VepTestCase, BASE_FILES
from vep import builds
from vep.builds import BuildAction
from vep.errors import AuthorizationError

GEN = ("import pathlib\npathlib.Path('out.txt').write_text(pathlib.Path('arithmetic.py').read_text().upper())\n")
NONDET = "import os, pathlib\npathlib.Path('out.txt').write_text(os.urandom(8).hex())\n"


def action(e, script, **kw):
    kw.setdefault("outputs", ("out.txt",))
    return BuildAction(("{python}", "-I", "-c", script), e.base.id, **kw)


class BuildTests(VepTestCase):
    def test_miss_then_verified_hit(self):
        e = self.env()
        a = action(e, GEN)
        r1 = builds.run(e.ws, a)
        self.assertEqual((r1["cache"], r1["failure"], r1["determinism_verified"]), ("MISS", None, True))
        r2 = builds.run(e.ws, a)
        self.assertEqual(r2["cache"], "HIT")
        self.assertEqual(r2["outputs"], r1["outputs"])
        self.assertEqual(e.ws.cas.get(r2["outputs"]["out.txt"]), BASE_FILES["arithmetic.py"].upper().encode())
        st = builds.stats(e.ws)
        self.assertEqual((st["MISS"]["count"], st["HIT"]["count"]), (1, 1))
        self.assertEqual(r2["executed_wall_s"], 0.0)

    def test_action_id_changes_with_every_input(self):
        e = self.env()
        base = builds.action_id(action(e, GEN))
        self.assertEqual(base, builds.action_id(action(e, GEN)))
        self.assertNotEqual(base, builds.action_id(action(e, GEN + "\n")))
        self.assertNotEqual(base, builds.action_id(action(e, GEN, outputs=("out.txt", "b"))))
        other = BuildAction(("{python}", "-I", "-c", GEN), self.env_snapshot_changed(e), ("out.txt",))
        self.assertNotEqual(base, builds.action_id(other))

    def env_snapshot_changed(self, e):
        from vep import snapshots
        d = e.variant({"arithmetic.py": "def add(a, b):\n    return b + a\n"})
        return snapshots.take_snapshot(e.ws, d).id

    def test_source_change_invalidates_cache(self):
        e = self.env()
        builds.run(e.ws, action(e, GEN))
        changed = BuildAction(("{python}", "-I", "-c", GEN), self.env_snapshot_changed(e), ("out.txt",))
        r = builds.run(e.ws, changed)
        self.assertEqual(r["cache"], "MISS")
        self.assertEqual(e.ws.cas.get(r["outputs"]["out.txt"]), b"DEF ADD(A, B):\n    RETURN B + A\n")

    def test_nondeterministic_action_is_not_cached(self):
        e = self.env()
        r = builds.run(e.ws, action(e, NONDET))
        self.assertEqual((r["failure"], r["cache"]), ("NONDETERMINISTIC", "NOT_CACHED"))
        self.assertIsNone(builds.lookup(e.ws, builds.action_id(action(e, NONDET))))

    def test_cache_policy_none_never_caches(self):
        e = self.env()
        a = action(e, NONDET, cache_policy="none")
        self.assertEqual(builds.run(e.ws, a)["cache"], "UNCACHEABLE")
        self.assertEqual(builds.run(e.ws, a)["cache"], "UNCACHEABLE")

    def test_corrupted_cache_entry_is_a_miss_not_a_reuse(self):
        e = self.env()
        a = action(e, GEN)
        r = builds.run(e.ws, a)
        blob = e.ws.cas._path(r["outputs"]["out.txt"]) if hasattr(e.ws.cas, "_path") else None
        os.chmod(blob, 0o644)
        blob.write_bytes(b"tampered")
        r2 = builds.run(e.ws, a)
        self.assertEqual(r2["cache"], "MISS")
        self.assertEqual(e.ws.cas.get(r2["outputs"]["out.txt"]), BASE_FILES["arithmetic.py"].upper().encode())

    def test_failures_are_classified_and_not_cached(self):
        e = self.env()
        self.assertEqual(builds.run(e.ws, action(e, "raise SystemExit(3)"))["failure"], "NONZERO_EXIT")
        self.assertEqual(builds.run(e.ws, action(e, "pass"))["failure"], "MISSING_OUTPUTS")
        t = builds.run(e.ws, action(e, "import time; time.sleep(30)", timeout_s=1))
        self.assertEqual(t["failure"], "TIMEOUT")
        self.assertIsNone(builds.lookup(e.ws, builds.action_id(action(e, "pass"))))

    def test_unsafe_actions_rejected(self):
        e = self.env()
        with self.assertRaises(AuthorizationError):
            builds.action_id(BuildAction(("python3", "-c", "1"), e.base.id))
        with self.assertRaises(AuthorizationError):
            builds.action_id(BuildAction(("{python}", "-c", "1"), e.base.id, env=(("LD_PRELOAD", "x"),)))
