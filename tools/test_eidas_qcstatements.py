import unittest
from eidas_qcstatements import oid, parse_qc, tlv
class QCStatementsTests(unittest.TestCase):
    def test_qc_compliance(self):
        self.assertEqual(parse_qc(bytes.fromhex("300a3008060604008e460101"))[0]["name"], "QcCompliance")
    def test_qscd(self):
        self.assertEqual(parse_qc(bytes.fromhex("300a3008060604008e460104"))[0]["name"], "QcSSCD")
    def test_qctype_esign(self):
        data=bytes.fromhex("30153013060604008e4601063009060704008e46010601")
        result=parse_qc(data)
        self.assertEqual(result[0]["certificate_types"][0]["oid"], "0.4.0.1862.1.6.1")
    def test_qctype_rejects_missing_info(self):
        with self.assertRaises(ValueError):
            parse_qc(bytes.fromhex("300a3008060604008e460106"))
    def test_qctype_rejects_wrong_info_tag(self):
        with self.assertRaises(ValueError):
            parse_qc(bytes.fromhex("300d300b060604008e460106310100"))
    def test_qctype_rejects_duplicate_type(self):
        with self.assertRaises(ValueError):
            parse_qc(bytes.fromhex("30163014060604008e460106300a06030400010603040001"))
    def test_qctype_unknown_type_is_not_esign(self):
        result=parse_qc(bytes.fromhex("3011300f060604008e46010630050603040007"))
        self.assertEqual(result[0]["certificate_types"][0]["name"], "unknown")
    def test_reject_truncated(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("300a3008"))
    def test_reject_indefinite(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("30800000"))
    def test_reject_wrong_outer_tag(self):
        with self.assertRaises(ValueError): parse_qc(bytes.fromhex("3100"))
    def test_reject_incomplete_oid(self):
        with self.assertRaises(ValueError): oid(bytes.fromhex("81"))
if __name__ == '__main__': unittest.main()
