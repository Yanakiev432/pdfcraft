# B-Trust real root certificate — offline evidence

The intermediate's AIA CA Issuers URL is `http://ca.b-trust.org/repository/B-TrustRootQCAOCSP.cer`. On 2026-10-18 the downloaded response contained a PEM certificate (despite its `.cer` extension). It was saved outside the Git repository at `/home/yanakiev/pdfcraft-eidas-evidence/btrust-root-candidate.pem`.

The DER SHA-256 of that certificate is `d33895e1d51123f948c8c999f7f72640fa0505fbd15ab093e898db27dd2914e8`.

Real offline run: `tools/eidas_root_link_verify.py` returned `caller_root_pin_matches: true`, `issuer_signature_by_root_verified: true`, `root_ca_constraints_verified: true`, `issuer_aki_matches_root_ski: true`, `root_valid_at_evaluation_time: true`, `root_self_signature_verified: true`, and `local_three_certificate_link_verified: true` at the caller-supplied evaluation instant 2026-10-18T14:30:00Z.

The integrated `tools/eidas_btrust_synthesis.py` accepts optional `--root-pem` and `--root-sha256` arguments. A root and its digest obtained from the same CA-hosted location **are not independently authenticated**. Root provenance remains false; no complete PKIX/eIDAS trust or trusted signing time is inferred. QES remains `Indeterminate`.

The certificate was not committed; no signer PII is included in this document.
