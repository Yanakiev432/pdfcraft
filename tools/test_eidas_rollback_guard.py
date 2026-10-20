import unittest
from eidas_rollback_guard import compare, snapshot, check, check_authenticated_acceptance
from pathlib import Path
from tempfile import TemporaryDirectory
class RollbackGuardTests(unittest.TestCase):
    old = {"sequence": 64, "issued": "2026-06-01T11:07:50+00:00"}
    def test_snapshot_records_hash_without_claiming_trust(self):
        xml = """<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation><TSLSequenceNumber>1</TSLSequenceNumber><ListIssueDateTime>2026-10-01T00:00:00Z</ListIssueDateTime><NextUpdate><dateTime>2026-11-01T00:00:00Z</dateTime></NextUpdate></SchemeInformation></TrustServiceStatusList>"""
        with TemporaryDirectory() as d:
            a, b = Path(d)/"eu.xml", Path(d)/"bg.xml"
            a.write_text(xml)
            b.write_text(xml)
            result = snapshot(a, b, "2026-10-18T00:00:00Z")
            self.assertEqual(result["schema"], "pdfcraft.eidas.rollback-snapshot.v1")
            self.assertEqual(len(result["eu"]["sha256"]), 64)
            self.assertEqual(result["eu"]["sha256"], result["national"]["sha256"])
            self.assertFalse(result["checkpoint_provenance_verified"])
            self.assertFalse(result["rollback_protection_verified"])
    def test_boolean_sequence_is_rejected(self):
        with self.assertRaises(ValueError):
            compare(dict(self.old, sequence=True), self.old)
    def test_new_sequence_with_unchanged_issue_date_is_ambiguous(self):
        self.assertTrue(compare(dict(self.old, sequence=65), self.old)["sequence_equivocation_detected"])
    def test_checkpoint_comparison_requires_schema_and_digests(self):
        entry = dict(self.old, sha256="a" * 64)
        record = {"schema": "pdfcraft.eidas.rollback-snapshot.v1", "eu": entry, "national": entry}
        self.assertFalse(check(record, record)["rollback_protection_verified"])
        with self.assertRaises(ValueError):
            check(dict(record, schema="other"), record)
        with self.assertRaises(ValueError):
            check(dict(record, national=self.old), record)
    def test_authenticated_acceptance_still_does_not_trust_baseline(self):
        entry = dict(self.old, sha256="a" * 64, within_publication_window=True)
        baseline = {"schema": "pdfcraft.eidas.rollback-snapshot.v1", "eu": entry, "national": entry}
        accepted = dict(baseline, eu_lotl_authenticated_at_evaluation_time=True,
                        national_tsl_authenticated_via_lotl=True)
        finding = check_authenticated_acceptance(accepted, baseline)
        self.assertTrue(finding["authenticated_current_lists"])
        self.assertFalse(finding["baseline_provenance_verified"])
        self.assertFalse(finding["rollback_protection_verified"])
    def test_unverified_acceptance_is_rejected(self):
        entry = dict(self.old, sha256="a" * 64, within_publication_window=True)
        baseline = {"schema": "pdfcraft.eidas.rollback-snapshot.v1", "eu": entry, "national": entry}
        for field in ("eu_lotl_authenticated_at_evaluation_time", "national_tsl_authenticated_via_lotl"):
            accepted = dict(baseline, eu_lotl_authenticated_at_evaluation_time=True,
                            national_tsl_authenticated_via_lotl=True)
            accepted[field] = False
            with self.assertRaises(ValueError): check_authenticated_acceptance(accepted, baseline)
        accepted[field] = True
        accepted["national"] = dict(entry, within_publication_window=False)
        with self.assertRaises(ValueError): check_authenticated_acceptance(accepted, baseline)
    def test_equal(self):
        self.assertTrue(compare(self.old, self.old)["not_older_than_checkpoint"])
    def test_sequence_rollback(self):
        self.assertTrue(compare({"sequence": 63, "issued": "2026-06-01T11:07:50Z"}, self.old)["rollback_detected"])
    def test_issue_date_rollback(self):
        self.assertTrue(compare({"sequence": 65, "issued": "2026-05-01T11:07:50Z"}, self.old)["rollback_detected"])
    def test_same_sequence_changed_date(self):
        self.assertTrue(compare({"sequence": 64, "issued": "2026-07-01T11:07:50Z"}, self.old)["sequence_equivocation_detected"])
    def test_same_sequence_same_date_different_content(self):
        previous = dict(self.old, sha256="a" * 64)
        current = dict(self.old, sha256="b" * 64)
        finding = compare(current, previous)
        self.assertTrue(finding["sequence_equivocation_detected"])
        self.assertFalse(finding["not_older_than_checkpoint"])
        self.assertTrue(finding["content_identity_compared"])
    def test_same_content(self):
        record = dict(self.old, sha256="a" * 64)
        self.assertTrue(compare(record, record)["not_older_than_checkpoint"])
    def test_invalid_digest_rejected(self):
        with self.assertRaises(ValueError):
            compare(dict(self.old, sha256="invalid"), self.old)
    def test_newer(self):
        self.assertTrue(compare({"sequence": 65, "issued": "2026-07-01T11:07:50Z"}, self.old)["not_older_than_checkpoint"])
    def test_naive_date_rejected(self):
        with self.assertRaises(ValueError): compare({"sequence": 65, "issued": "2026-07-01"}, self.old)
if __name__ == '__main__': unittest.main()
