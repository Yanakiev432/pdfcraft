import unittest
from eidas_qcstatements import oid, parse_qc, tlv
class QCStatementsTests(unittest.TestCase):
    def test_qc_compliance(self):
        self.assertEqual(parse_qc(bytes.fromhex("300a3008060604008e460101"))[0]["name"], "QcCompliance")
    def test_qscd(self):
        self.assertEqual(parse_qc(bytes.fromhex("300a3008060604008e460104"))[0]["name"], "QcSSCD")
    def test_reject_truncated(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("300a3008"))
    def test_reject_indefinite(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("30800000"))
    def test_reject_wrong_outer_tag(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("3100"))
    def test_reject_incomplete_oid(self):
        with self.assertRaises(ValueError): oid(bytes.fromhex("81"))
if __name__ == '__main__': unittest.main()
