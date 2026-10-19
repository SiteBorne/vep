import unittest

from vep.canonical import canonical_bytes, domain_hash, strict_loads
from vep.errors import CanonicalError, SchemaError
from vep.objects import VEPObject, parse_id

OBS = {"subject": "s", "metric": "m", "value": "1.5", "unit": "x", "source": "measured",
       "observed_at": "2026-01-01T00:00:00Z"}


class CanonicalTests(unittest.TestCase):
    def test_key_order_and_whitespace_irrelevant(self):
        self.assertEqual(canonical_bytes({"b": 1, "a": [1, 2]}), b'{"a":[1,2],"b":1}')
        self.assertEqual(canonical_bytes(strict_loads('{ "b" : 1, "a":[1, 2] }')), b'{"a":[1,2],"b":1}')

    def test_golden_identities_are_stable(self):
        # Pinned digests: any change to canonicalization or domain separation breaks these on purpose.
        obj = VEPObject.create("Observation", OBS)
        self.assertEqual(obj.id, VEPObject.create("Observation", dict(reversed(list(OBS.items())))).id)
        self.assertEqual(obj.id, GOLDEN_OBSERVATION_ID)

    def test_domain_separation(self):
        self.assertNotEqual(domain_hash("a", b"bc"), domain_hash("ab", b"c"))
        self.assertNotEqual(domain_hash("vep.X.v1", b"{}"), domain_hash("vep.Y.v1", b"{}"))

    def test_rejects_duplicates_floats_nonfinite(self):
        for bad in ('{"a":1,"a":2}', '{"a":1.5}', '{"a":NaN}', '{"a":Infinity}', '[1e400]'):
            with self.assertRaises(CanonicalError, msg=bad):
                strict_loads(bad)
        with self.assertRaises(CanonicalError):
            canonical_bytes({"a": 0.1})
        with self.assertRaises(CanonicalError):
            canonical_bytes({"a": 2**70})
        with self.assertRaises(CanonicalError):
            canonical_bytes({1: "x"})

    def test_object_validation(self):
        with self.assertRaises(SchemaError):
            VEPObject.create("Observation", {**OBS, "extra": "x"})
        with self.assertRaises(SchemaError):
            VEPObject.create("Observation", {**OBS, "value": "1e5"})
        with self.assertRaises(SchemaError):
            VEPObject.create("Observation", {**OBS, "source": "guess"})
        with self.assertRaises(SchemaError):
            VEPObject.create("Nope", {})
        missing = dict(OBS); del missing["unit"]
        with self.assertRaises(SchemaError):
            VEPObject.create("Observation", missing)

    def test_roundtrip_and_noncanonical_rejected(self):
        obj = VEPObject.create("Observation", OBS)
        self.assertEqual(VEPObject.from_bytes(obj.canonical_bytes()).id, obj.id)
        with self.assertRaises(SchemaError):
            VEPObject.from_bytes(obj.canonical_bytes().replace(b",", b", "))
        with self.assertRaises(CanonicalError):
            VEPObject.from_bytes(b'{"type":"Observation","type":"x"}')

    def test_ids_are_typed(self):
        obj = VEPObject.create("Observation", OBS)
        self.assertEqual(parse_id(obj.id)[0], "Observation")
        with self.assertRaises(SchemaError):
            parse_id("obs-zz")
        with self.assertRaises(SchemaError):
            VEPObject.create("Candidate", {"objective_id": obj.id})


GOLDEN_OBSERVATION_ID = "obs-c956a8b7debe5ece7f0d146b91a7a08717a824dc78ce61ddd0ebc75325458600"

if __name__ == "__main__":
    unittest.main()
