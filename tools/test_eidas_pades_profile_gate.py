"""Fail-closed acceptance tests. No real keys, networking or tokens."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from eidas_pades_profile_gate import evaluate, verify_current_file

BASE = {
    "schema": "pdfcraft.eidas.independent-dss.v1",
    "independent_dss_qes_pass": True,
    "dss_indication": "TOTAL_PASSED",
    "dss_signature_level": "QESig",
    "dss_signature_format": "PAdES-BASELINE-B",
    "pdf_sha256": "0" * 64,
}

class ProfileTests(unittest.TestCase):
    def test_b_only_does_not_pretend_to_be_t_lt_lta(self):
        self.assertTrue(evaluate(BASE, "B")["gate_pass"])
        for level in ("T", "LT", "LTA"):
            self.assertFalse(evaluate(BASE, level)["gate_pass"])

    def test_levels_require_explicit_independent_evidence(self):
        for index, level in enumerate(("B", "T", "LT", "LTA")):
            report = dict(BASE, dss_signature_format="PAdES-BASELINE-" + level)
            for position, minimum in enumerate(("B", "T", "LT", "LTA")):
                self.assertEqual(evaluate(report, minimum)["gate_pass"], index >= position)

    def test_no_fallback_from_unknown_or_nonqualified_format(self):
        for fmt in ("PAdES-B-T", "PAdES-BASELINE-Z", None, "PAdES-BASELINE-B;LTA"):
            self.assertFalse(evaluate(dict(BASE, dss_signature_format=fmt), "B")["gate_pass"])
        for item in (dict(BASE, dss_signature_level="AdES"), dict(BASE, dss_indication="INDETERMINATE"),
                     dict(BASE, independent_dss_qes_pass=False), dict(BASE, schema="wrong")):
            self.assertFalse(evaluate(item, "B")["gate_pass"])

    def test_file_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            pdf = Path(root) / "signed.pdf"
            pdf.write_bytes(b"original")
            correct_hash = hashlib.sha256(b"original").hexdigest()
            def correct(_):
                return dict(BASE, pdf_sha256=correct_hash), b""
            def substituted(_):
                pdf.write_bytes(b"changed externally")
                return dict(BASE, pdf_sha256=correct_hash), b""
            self.assertTrue(verify_current_file(pdf, "B", correct)["gate_pass"])
            self.assertFalse(verify_current_file(pdf, "B", substituted)["gate_pass"])

if __name__ == "__main__":
    unittest.main()
