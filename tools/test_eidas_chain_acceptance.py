import unittest
from eidas_chain_acceptance import timestamp, safe_tsl_root
from tempfile import TemporaryDirectory
from pathlib import Path
class AcceptanceTests(unittest.TestCase):
    def test_timezone(self):
        self.assertEqual(timestamp("2026-10-17T23:00:00+03:00").isoformat(), "2026-10-17T20:00:00+00:00")
    def test_rejects_doctype_entity_and_wrong_root(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tsl.xml"
            for xml in (b"<!DOCTYPE x><TrustServiceStatusList/>",
                        b"<!ENTITY x SYSTEM 'file:///etc/passwd'><TrustServiceStatusList/>",
                        b"<Unexpected/>", b""):
                p.write_bytes(xml)
                with self.assertRaises(ValueError): safe_tsl_root(p)
    def test_rejects_oversized_xml(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "tsl.xml"
            p.write_bytes(b"x" * (8388608 + 1))
            with self.assertRaises(ValueError): safe_tsl_root(p)
    def test_naive_rejected(self):
        with self.assertRaises(ValueError): timestamp("2026-10-17T20:00:00")
if __name__ == '__main__': unittest.main()
