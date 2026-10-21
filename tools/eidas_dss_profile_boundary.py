#!/usr/bin/env python3
"""Read-only profile assessment of the exact local EU DSS validation response.

A PAdES format label is NOT proof of a qualified RFC3161 TSA. This script
never upgrades a B-level QES into a B-T/LT/LTA or eIDAS QTSA acceptance,
and never sends user files beyond the explicitly configured loopback DSS.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

PROFILES = {
    "PAdES-BASELINE-B": "B",
    "PAdES-BASELINE-T": "B-T",
    "PAdES-BASELINE-LT": "B-LT",
    "PAdES-BASELINE-LTA": "B-LTA",
}
MAX_PDF = 64 * 1024 * 1024


class EvidenceRejected(ValueError):
    pass


def _require(condition: bool, text: str) -> None:
    if not condition:
        raise EvidenceRejected(text)


def _only_signature(simple: dict) -> dict:
    _require(isinstance(simple, dict), "DSS SimpleReport missing")
    _require(type(simple.get("SignaturesCount")) is int and simple["SignaturesCount"] == 1, "expected one reported signature")
    _require(type(simple.get("ValidSignaturesCount")) is int and simple["ValidSignaturesCount"] == 1, "expected one valid signature")
    items = simple.get("signatureOrTimestampOrEvidenceRecord")
    _require(isinstance(items, list) and len(items) == 1, "unexpected independent DSS signature count")
    item = items[0]
    _require(isinstance(item, dict) and set(item) == {"Signature"}, "unexpected top-level timestamp or evidence record")
    signature = item["Signature"]
    _require(isinstance(signature, dict), "signature node missing")
    return signature


def classify_dss_response(raw: bytes, adapter_summary: dict) -> dict:
    """Classify ONLY the DSS report returned for this exact request; no QTSA proof."""
    _require(isinstance(raw, bytes) and 0 < len(raw) <= 16 * 1024 * 1024, "bounded raw DSS report required")
    _require(isinstance(adapter_summary, dict) and adapter_summary.get("schema") == "pdfcraft.eidas.independent-dss.v1", "wrong validator source")
    _require(adapter_summary.get("dss_report_sha256") == hashlib.sha256(raw).hexdigest(), "raw report digest disagrees with adapter summary")
    _require(isinstance(adapter_summary.get("pdf_sha256"), str) and len(adapter_summary["pdf_sha256"]) == 64, "PDF SHA256 missing")
    try:
        report = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceRejected("invalid raw DSS JSON") from exc
    _require(isinstance(report, dict) and isinstance(report.get("SimpleReport"), dict), "DSS SimpleReport absent")
    signature = _only_signature(report["SimpleReport"])
    fmt = signature.get("SignatureFormat")
    _require(isinstance(fmt, str) and fmt in PROFILES, "unsupported or unrecognized PAdES format")
    _require(signature.get("Indication") == "TOTAL_PASSED", "signature validity not TOTAL_PASSED")
    level = signature.get("SignatureLevel")
    _require(isinstance(level, dict) and level.get("value") == "QESig", "DSS qualification is not QESig")
    _require(adapter_summary.get("dss_signature_format") == fmt, "signature format mismatch with original adapter")
    _require(adapter_summary.get("dss_indication") == "TOTAL_PASSED", "adapter indication mismatch")
    _require(adapter_summary.get("dss_signature_level") == "QESig", "adapter qualification mismatch")
    _require(adapter_summary.get("independent_dss_qes_pass") is True, "adapter rejected QES")
    stamps = signature.get("Timestamps")
    stamp_count = 0
    stamp_status = "ABSENT"
    if stamps is not None:
        _require(isinstance(stamps, list), "Timestamps must be a list or null")
        stamp_count = len(stamps)
        _require(stamp_count <= 64, "unbounded timestamp count")
        for stamp in stamps:
            _require(isinstance(stamp, dict) and set(stamp) == {"Timestamp"}, "unrecognized DSS timestamp node")
            node = stamp["Timestamp"]
            _require(isinstance(node, dict) and node.get("Indication") == "TOTAL_PASSED", "timestamp integrity not TOTAL_PASSED")
        stamp_status = "DSS_TOTAL_PASSED" if stamp_count else "ABSENT"
    minimum = PROFILES[fmt]
    # Trusted-list service status at production time is NOT supplied by this
    # SimpleReport classification. Do not turn the presence of a timestamp
    # or a B-LT/B-LTA format label into a qualified timestamp endorsement.
    _require(minimum == "B" or stamp_count > 0, "timestamped profile without validated timestamp records")
    return {
        "schema": "pdfcraft.eidas.dss-profile-boundary.v1",
        "pdf_sha256": adapter_summary["pdf_sha256"],
        "raw_dss_report_sha256": hashlib.sha256(raw).hexdigest(),
        "dss_observed_profile": fmt,
        "dss_reported_signature_level": "QESig",
        "dss_reported_indication": "TOTAL_PASSED",
        "dss_profile_structural_level": minimum,
        "dss_timestamp_records": stamp_count,
        "dss_timestamp_integrity": stamp_status,
        "independent_dss_qes_at_observed_validation": True,
        "qualified_rfc3161_qtsa_at_generation_time": "NOT_CHECKED",
        "eu_lotl_national_tlv6_authenticity": "NOT_CHECKED_BY_THIS_CLASSIFIER",
        "dss_runtime_version_and_trust_policy": "NOT_ATTESTED_BY_THIS_CLASSIFIER",
        "qualified_pades_b_t_b_lt_b_lta_acceptance": "NO_GO",
        "user_document_or_certificate_exported": False,
        "release_ready": False,
    }


def local_report(pdf: Path):
    _require(pdf.is_file(), "local signed PDF is required")
    _require(0 < pdf.stat().st_size <= MAX_PDF, "PDF exceeds local DSS cap")
    adapter_path = Path(__file__).with_name("eidas_dss_local_verify.py")
    spec = importlib.util.spec_from_file_location("pdfcraft_local_dss_adapter", adapter_path)
    _require(spec is not None and spec.loader is not None, "local DSS adapter not found")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # validate() only contacts the opt-in DSS loopback host and prohibits
    # proxying/redirecting. Never accept an arbitrary remote validator URL.
    summary, raw = module.validate(pdf)
    classified = classify_dss_response(raw, summary)
    # Bind raw DSS report to unchanged file bytes; length/mtime alone are
    # insufficient since attackers can restore those attributes.
    hash_after = hashlib.sha256()
    with pdf.open("rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            hash_after.update(block)
    _require(hash_after.hexdigest() == classified["pdf_sha256"], "PDF changed during or after independent DSS validation")
    return classified


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: eidas_dss_profile_boundary.py original-signed.pdf")
    try:
        output = local_report(Path(sys.argv[1]))
    except (EvidenceRejected, OSError, ValueError) as exc:
        # Never log certificate details, source paths or entire raw reports.
        print("INDEPENDENT_DSS_PROFILE_NO_GO: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
