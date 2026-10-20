#!/usr/bin/env python3
"""Fail-closed, local-EU-DSS PAdES profile acceptance gate.

An observed PDF dictionary or CMS timestamp attribute does not prove PAdES
B-T/B-LT/B-LTA qualification. This checks the actual independent DSS response
and binds the result to the current PDF bytes. It does not issue new signatures.
"""
import argparse
import hashlib
import json
from pathlib import Path

# Import a fixed sibling file even with Python isolated mode (-I).
import importlib.util

_ADAPTER = Path(__file__).resolve().with_name("eidas_dss_local_verify.py")
_spec = importlib.util.spec_from_file_location("pdfcraft_local_dss_adapter", _ADAPTER)
if _spec is None or _spec.loader is None:
    raise RuntimeError("The sibling EU DSS adapter is missing")
_adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_adapter)
validate = _adapter.validate

PROFILES = {"B": 0, "T": 1, "LT": 2, "LTA": 3}
FORMATS = {level: "PAdES-BASELINE-" + level for level in PROFILES}


def evaluate(report, minimum):
    """Classify only explicit DSS-validated formats, never a guessed PDF structure."""
    if minimum not in PROFILES:
        raise ValueError("Unsupported required profile")
    raw_format = report.get("dss_signature_format")
    recognized = next((label for label, fmt in FORMATS.items() if raw_format == fmt), None)
    valid_qes = (
        report.get("schema") == "pdfcraft.eidas.independent-dss.v1"
        and report.get("independent_dss_qes_pass") is True
        and report.get("dss_indication") == "TOTAL_PASSED"
        and report.get("dss_signature_level") == "QESig"
        and isinstance(report.get("pdf_sha256"), str)
        and len(report["pdf_sha256"]) == 64
    )
    meets = valid_qes and recognized is not None and PROFILES[recognized] >= PROFILES[minimum]
    return {
        "schema": "pdfcraft.pades.independent-profile-gate.v1",
        "required_minimum": minimum,
        "observed_dss_format": raw_format,
        "recognized_profile": recognized,
        "observed_qes": valid_qes,
        "gate_pass": bool(meets),
        "evidence_source": "local EU DSS independent validator; no format inferred from PDF metadata",
        "qualified_timestamp_proven_by_this_gate": False,
        "trusted_revocation_archival_proven_by_this_gate": False,
        "note": "A format/QES classification is not independent certification of a particular TSA, trust-list history or archival renewal policy.",
    }


def verify_current_file(pdf, minimum, validator=validate):
    pdf = Path(pdf)
    result, _raw_report = validator(str(pdf))
    expected = result.get("pdf_sha256", "")
    actual = hashlib.sha256(pdf.read_bytes()).hexdigest()
    out = evaluate(result, minimum)
    out["pdf_sha256"] = actual
    out["sha256_bound_to_current_file"] = isinstance(expected, str) and expected == actual
    out["gate_pass"] = bool(out["gate_pass"] and out["sha256_bound_to_current_file"])
    return out


def main():
    parser = argparse.ArgumentParser(description="Reject unsigned, unqualified or insufficiently timestamped PAdES profiles")
    parser.add_argument("pdf", help="Existing PDF to validate locally; no signing performed")
    parser.add_argument("--minimum", choices=list(PROFILES), required=True)
    args = parser.parse_args()
    try:
        out = verify_current_file(args.pdf, args.minimum)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        print(json.dumps({"schema": "pdfcraft.pades.independent-profile-gate.v1", "gate_pass": False,
                          "reason": f"{type(exc).__name__}: {exc}"}))
        return 2
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
