#!/usr/bin/env python3
"""Synthetic redacted DSS SimpleReport tests; no B-Trust identity/PDF/network."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

here=Path(__file__).with_name("eidas_dss_profile_boundary.py")
spec=importlib.util.spec_from_file_location("profile_boundary",here)
assert spec and spec.loader
app=importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


def fixture(profile="PAdES-BASELINE-B", timestamps=None):
    node={
        "SignatureFormat":profile,
        "Indication":"TOTAL_PASSED",
        "SubIndication":None,
        "SignatureLevel":{"value":"QESig","description":"Qualified"},
        "Timestamps":timestamps,
    }
    response={
        "SimpleReport":{
            "SignaturesCount":1,
            "ValidSignaturesCount":1,
            "signatureOrTimestampOrEvidenceRecord":[{"Signature":node}],
            "ValidationTime":"2026-10-21T11:00:00Z",
        }
    }
    raw=json.dumps(response,separators=(",",":"),sort_keys=True).encode("utf-8")
    summary={
        "schema":"pdfcraft.eidas.independent-dss.v1",
        "pdf_sha256":"a"*64,
        "dss_report_sha256":hashlib.sha256(raw).hexdigest(),
        "dss_signature_format":profile,
        "dss_indication":"TOTAL_PASSED",
        "dss_signature_level":"QESig",
        "independent_dss_qes_pass":True,
    }
    return response,raw,summary


def repack(report,summary):
    raw=json.dumps(report,separators=(",",":"),sort_keys=True).encode("utf-8")
    summary=dict(summary)
    summary["dss_report_sha256"]=hashlib.sha256(raw).hexdigest()
    return raw,summary


class DssProfileBoundaryTests(unittest.TestCase):
    def test_real_btrust_style_baseline_b_cannot_be_promoted_to_b_t(self):
        _,raw,summary=fixture()
        result=app.classify_dss_response(raw,summary)
        self.assertEqual(result["dss_profile_structural_level"],"B")
        self.assertEqual(result["dss_timestamp_records"],0)
        self.assertEqual(result["qualified_rfc3161_qtsa_at_generation_time"],"NOT_CHECKED")
        self.assertEqual(result["qualified_pades_b_t_b_lt_b_lta_acceptance"],"NO_GO")
        self.assertTrue(result["independent_dss_qes_at_observed_validation"])
        self.assertFalse(result["release_ready"])

    def test_valid_synthetic_t_lt_lta_are_still_not_qualified(self):
        stamped=[{"Timestamp":{"Indication":"TOTAL_PASSED","SignatureLevel":{"value":"TSA"}}}]
        for suffix in ("T","LT","LTA"):
            with self.subTest(profile=suffix):
                _,raw,summary=fixture("PAdES-BASELINE-"+suffix, stamped)
                data=app.classify_dss_response(raw,summary)
                self.assertEqual(data["dss_profile_structural_level"], "B-"+suffix)
                self.assertEqual(data["dss_timestamp_integrity"],"DSS_TOTAL_PASSED")
                self.assertEqual(data["qualified_pades_b_t_b_lt_b_lta_acceptance"],"NO_GO")

    def test_timestamped_format_without_timestamp_records_fails(self):
        for fmt in ("PAdES-BASELINE-T","PAdES-BASELINE-LT","PAdES-BASELINE-LTA"):
            with self.subTest(fmt=fmt):
                _,raw,s=fixture(fmt,None)
                with self.assertRaises(app.EvidenceRejected):
                    app.classify_dss_response(raw,s)

    def test_timestamp_signature_not_passed_fails(self):
        bad=[{"Timestamp":{"Indication":"INDETERMINATE"}}]
        _,raw,s=fixture("PAdES-BASELINE-T",bad)
        with self.assertRaises(app.EvidenceRejected):
            app.classify_dss_response(raw,s)

    def test_disagreeing_summary_digest_fails(self):
        _,raw,s=fixture()
        s["dss_report_sha256"]="0"*64
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)

    def test_disagreeing_adapter_format_fails(self):
        _,raw,s=fixture()
        s["dss_signature_format"]="PAdES-BASELINE-T"
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)

    def test_disagreeing_adapter_qes_fails(self):
        _,raw,s=fixture()
        s["independent_dss_qes_pass"]=False
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)

    def test_dss_one_valid_of_two_signatures_fails(self):
        obj,_,s=fixture()
        obj["SimpleReport"]["SignaturesCount"]=2
        raw,s=repack(obj,s)
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)

    def test_top_level_timestamp_masquerading_as_signature_fails(self):
        obj,_,s=fixture()
        obj["SimpleReport"]["signatureOrTimestampOrEvidenceRecord"]=[{"Timestamp":{"Indication":"TOTAL_PASSED"}}]
        raw,s=repack(obj,s)
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)

    def test_unrecognized_pades_format_fails(self):
        obj,_,s=fixture("PAdES-BASELINE-H")
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(json.dumps(obj).encode(),s)

    def test_no_raw_certificate_data_in_output(self):
        obj,_,s=fixture()
        obj["SimpleReport"]["signatureOrTimestampOrEvidenceRecord"][0]["Signature"]["SignedBy"]="PRIVATE_PERSONAL_SUBJECT"
        raw,s=repack(obj,s)
        output=app.classify_dss_response(raw,s)
        self.assertNotIn("PRIVATE_PERSONAL_SUBJECT",json.dumps(output))
        self.assertNotIn("SignedBy",output)

    def test_reject_boolean_signature_counter(self):
        obj,_,s=fixture()
        obj["SimpleReport"]["SignaturesCount"]=True
        raw,s=repack(obj,s)
        with self.assertRaises(app.EvidenceRejected):app.classify_dss_response(raw,s)


if __name__=="__main__":
    unittest.main(verbosity=2)
