#!/usr/bin/env python3
"""Combine independently checked CRL and OCSP observations without promoting QES."""
import argparse
import hashlib
import json
from pathlib import Path
from eidas_crl_verify import inspect as inspect_crl, utc
from eidas_ocsp_verify import inspect as inspect_ocsp

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def combine(crl, ocsp):
    statuses = (crl["revocation_status"], ocsp["revocation_status"])
    if "Revoked" in statuses:
        combined = "RevokedObserved"
    elif statuses == ("GoodAtEvaluationTime", "GoodAtEvaluationTime"):
        combined = "ConcordantGoodAtEvaluationTime"
    elif "IndeterminateHistorical" in statuses:
        combined = "IndeterminateHistorical"
    else:
        combined = "InsufficientOrDiscordant"
    return combined

def inspect(pem, crl_path, ocsp_path, evaluation_time):
    utc(evaluation_time)
    crl = inspect_crl(pem, crl_path, evaluation_time)
    ocsp = inspect_ocsp(pem, ocsp_path, evaluation_time)
    return {
        "schema": "pdfcraft.eidas.revocation-evidence.v1",
        "evaluation_time_claim": evaluation_time,
        "evaluation_time_trusted": False,
        "issuer_path_verified": False,
        "inputs_sha256": {"certificate_bundle": digest(pem), "crl": digest(crl_path), "ocsp": digest(ocsp_path)},
        "crl": crl, "ocsp": ocsp,
        "combined_observation": combine(crl, ocsp),
        "rust_revocation_provenance": {
            "issuer_chain_verified": False,
            "response_signature_verified": bool(crl["crl_signature_verified"] and ocsp["response_signature_verified"]),
            "certificate_identity_verified": bool(crl["crl_issuer_matches"] and ocsp["certificate_id_matches"]),
            "scope_and_freshness_verified": bool(crl["crl_scope_supported"] and crl["crl_valid_at_evaluation_time"] and ocsp["response_fresh_at_evaluation_time"]),
            "trusted_evaluation_time": False,
        },
        "rust_admissible_revocation": "Unavailable",
        "qualification": "Indeterminate",
    }

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("certificates_pem")
    parser.add_argument("crl")
    parser.add_argument("ocsp_der")
    parser.add_argument("evaluation_time")
    args=parser.parse_args()
    print(json.dumps(inspect(args.certificates_pem,args.crl,args.ocsp_der,args.evaluation_time),indent=2))
