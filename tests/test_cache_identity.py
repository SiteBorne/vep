"""P0 reproduction and regression: build-action identity must cover the whole execution contract; a cache hit must not upgrade assurance."""
import unittest

from tests.helpers import VepTestCase
from vep import builds
from vep.builds import BuildAction

GEN = "import pathlib; pathlib.Path('out.txt').write_text('x')"


def act(e, **kw):
    kw.setdefault("outputs", ("out.txt",))
    return BuildAction(("{python}", "-I", "-c", GEN), e.base.id, **kw)


class IdentityTests(VepTestCase):
    def test_timeout_is_part_of_the_execution_contract(self):
        e = self.env()
        self.assertNotEqual(builds.action_id(act(e, timeout_s=300)), builds.action_id(act(e, timeout_s=5)))

    def test_every_material_input_changes_the_identity(self):
        e = self.env()
        base = builds.action_id(act(e))
        for variant in (act(e, timeout_s=7), act(e, env=(("LANG", "C"),)), act(e, outputs=("out.txt", "b.txt")), act(e, cache_policy="none"),
                        act(e, declared_dependencies=("requirements.lock@sha256:" + "a" * 64,))):
            self.assertNotEqual(base, builds.action_id(variant))
        self.assertEqual(base, builds.action_id(act(e)))
        self.assertEqual(base, builds.action_id(act(e, verify_determinism=False)))  # assurance is a property of the entry, not of the identity

    def test_unsupported_isolation_is_rejected_not_ignored(self):
        e = self.env()
        with self.assertRaises(Exception):
            builds.action_id(act(e, isolation="DOCKER_GVISOR"))

    def test_identity_domain_is_versioned_so_old_entries_cannot_be_reached(self):
        e = self.env()
        self.assertTrue(builds.action_id(act(e)).startswith("bact2-"))
        self.assertEqual(builds.BUILD_ACTION_VERSION, 2)


class AssuranceTests(VepTestCase):
    def test_a_single_run_result_is_never_reported_as_determinism_verified_on_a_hit(self):
        e = self.env()
        r1 = builds.run(e.ws, act(e, verify_determinism=False))
        self.assertEqual((r1["cache"], r1["determinism_verified"], r1["reproducibility_assurance"]), ("MISS", False, "SINGLE_RUN"))
        r2 = builds.run(e.ws, act(e, verify_determinism=False))
        self.assertEqual((r2["cache"], r2["determinism_verified"], r2["reproducibility_assurance"]), ("HIT", False, "SINGLE_RUN"))

    def test_a_caller_that_requires_verification_does_not_accept_an_unverified_entry(self):
        e = self.env()
        builds.run(e.ws, act(e, verify_determinism=False))
        r = builds.run(e.ws, act(e, verify_determinism=True))
        self.assertEqual((r["cache"], r["determinism_verified"]), ("MISS", True))  # re-executed twice, assurance upgraded
        r = builds.run(e.ws, act(e, verify_determinism=True))
        self.assertEqual((r["cache"], r["determinism_verified"], r["reproducibility_assurance"]), ("HIT", True, "TWO_RUN_MATCH"))
        r = builds.run(e.ws, act(e, verify_determinism=False))
        self.assertEqual((r["cache"], r["determinism_verified"]), ("HIT", True))  # a stronger entry satisfies a weaker request

    def test_two_matching_runs_are_described_as_exactly_that(self):
        e = self.env()
        r = builds.run(e.ws, act(e))
        self.assertIn("not a proof", r["assurance_note"])

    def test_entries_written_by_the_old_format_are_not_reusable(self):
        e = self.env()
        with e.ws.db.tx() as c:  # simulate a v1 entry: old-style id, no assurance field
            c.execute("INSERT INTO build_cache(action_id,result_digest,created_at) VALUES(?,?,?)", ("bact-" + "0" * 64, e.ws.cas.put(b'{"v":1}'), "2026-01-01T00:00:00Z"))
        self.assertIsNone(builds.lookup(e.ws, "bact-" + "0" * 64))


if __name__ == "__main__":
    unittest.main()
