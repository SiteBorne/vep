import os
import unittest
from pathlib import Path

from vep.errors import CorruptObject, ObjectNotFound, VepError
from vep.storage import CAS
from tests.helpers import VepTestCase


class CASTests(VepTestCase):
    def setUp(self):
        super().setUp()
        self.cas = CAS(self.tmp / "cas")

    def test_put_get_roundtrip_and_identity(self):
        d = self.cas.put(b"hello")
        self.assertEqual(d, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(self.cas.get(d), b"hello")
        self.assertTrue(self.cas.exists(d))
        self.assertTrue(self.cas.verify(d))

    def test_duplicate_write_elimination(self):
        d1, d2 = self.cas.put(b"x"), self.cas.put(b"x")
        self.assertEqual(d1, d2)
        files = [p for p in (self.tmp / "cas" / "objects").rglob("*") if p.is_file()]
        self.assertEqual(len(files), 1)

    def test_corruption_detected_on_get_and_verify(self):
        d = self.cas.put(b"payload")
        path = self.cas._path(d)
        os.chmod(path, 0o644)
        path.write_bytes(b"tampered")
        with self.assertRaises(CorruptObject):
            self.cas.get(d)
        self.assertFalse(self.cas.verify(d))

    def test_rewrite_repairs_corrupt_object(self):
        d = self.cas.put(b"payload")
        path = self.cas._path(d)
        os.chmod(path, 0o644)
        path.write_bytes(b"bad")
        self.assertEqual(self.cas.put(b"payload"), d)
        self.assertEqual(self.cas.get(d), b"payload")

    def test_missing_object_error(self):
        with self.assertRaises(ObjectNotFound):
            self.cas.get("0" * 64)
        self.assertFalse(self.cas.exists("0" * 64))
        self.assertFalse(self.cas.verify("0" * 64))

    def test_no_path_traversal_via_identifiers(self):
        for bad in ("../../etc/passwd", "../" + "a" * 61, "a" * 63, "A" * 64, "", "a/b", "..", "a" * 64 + "/x"):
            with self.assertRaises(VepError, msg=bad):
                self.cas.get(bad)
            with self.assertRaises(VepError):
                self.cas.exists(bad)

    def test_atomic_write_leaves_no_temp_files(self):
        self.cas.put(b"a")
        self.assertEqual(list((self.tmp / "cas" / "tmp").iterdir()), [])

    def test_failed_write_leaves_no_partial_object(self):
        with self.assertRaises(VepError):
            self.cas.put("not bytes")  # type: ignore[arg-type]
        self.assertEqual([p for p in (self.tmp / "cas" / "objects").rglob("*") if p.is_file()], [])

    def test_filename_is_not_trusted(self):
        d = self.cas.put(b"real")
        other = self.cas.put(b"other")
        wrong = self.cas._path(d)
        os.chmod(wrong, 0o644)
        wrong.write_bytes(self.cas.get(other))  # valid content under the wrong name
        with self.assertRaises(CorruptObject):
            self.cas.get(d)


if __name__ == "__main__":
    unittest.main()
