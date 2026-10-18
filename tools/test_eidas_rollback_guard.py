import unittest
from eidas_rollback_guard import compare
class RollbackGuardTests(unittest.TestCase):
    old = {"sequence": 64, "issued": "2026-06-01T11:07:50+00:00"}
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
