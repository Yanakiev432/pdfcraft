# Offline OCSP verification boundary

`tools/eidas_ocsp_verify.py` verifies a DER OCSP response against an explicitly supplied leaf and issuer PEM bundle. It matches the complete CertID, verifies response signature, delegated responder certificate signature and OCSPSigning EKU/digitalSignature key usage, responder identity, and response freshness against a caller-supplied timezone-aware evaluation time.

The verifier does not establish independent trust of the issuer CA, authenticated evaluation/signing time, certificate policy/QSCD qualification, historical status at the PDF-declared time, or full eIDAS trust-list validation. No OCSP `GOOD` result is directly admitted into Rust `QualificationEvidence` without its separate provenance gate.

Real B-Trust response at supplied `2026-10-17T20:45:00Z`: signature, responder authorization, CertID and freshness pass; status `GoodAtEvaluationTime`; issuer_path_verified=false, trusted_evaluation_time=false, qualification=Indeterminate. Response bytes and personal certificates remain outside Git.
