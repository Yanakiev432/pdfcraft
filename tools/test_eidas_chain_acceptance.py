import unittest
from eidas_chain_acceptance import timestamp, safe_tsl_root, acceptance
from unittest.mock import patch
import hashlib
from tempfile import TemporaryDirectory
from pathlib import Path
class AcceptanceTests(unittest.TestCase):
    def test_acceptance_includes_exact_input_digests(self):
        ns = "http://uri.etsi.org/02231/v2#"
        def xml(territory):
            return (f"<TrustServiceStatusList xmlns='{ns}'><SchemeInformation><SchemeTerritory>{territory}</SchemeTerritory><TSLSequenceNumber>1</TSLSequenceNumber><ListIssueDateTime>2026-10-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-11-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></TrustServiceStatusList>").encode()
        with TemporaryDirectory() as d:
            eu, bg = Path(d)/"eu.xml", Path(d)/"bg.xml"
            eu.write_bytes(xml("EU")); bg.write_bytes(xml("BG"))
            with patch("eidas_chain_acceptance.verify_eu", return_value={"lotl_authenticated": True}), patch("eidas_chain_acceptance.verify_xml", return_value={"cryptography_verified_with_untrusted_embedded_key": True}), patch("eidas_chain_acceptance.match_national", return_value={"pointers_unverified": [{"matching_signer_certificate": True, "location_unverified": "https://crc.bg/files/_en/TSL_BG.xml"}]}):
                result = acceptance(eu, bg, "2026-10-18T00:00:00Z")
            self.assertEqual(result["eu"]["sha256"], hashlib.sha256(eu.read_bytes()).hexdigest())
            self.assertEqual(result["national"]["sha256"], hashlib.sha256(bg.read_bytes()).hexdigest())
            self.assertTrue(result["national_tsl_authenticated_via_lotl"])
            self.assertFalse(result["rollback_protection_verified"])
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
