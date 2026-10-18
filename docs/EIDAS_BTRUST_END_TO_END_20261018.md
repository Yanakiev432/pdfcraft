# B-Trust CRL/OCSP to Rust end-to-end acceptance — 2026-10-18

Read-only evidence from the private WSL evidence directory is processed by `tools/eidas_revocation_report.py` into a local JSON file. The Rust `external_python_evidence_report_remains_indeterminate` regression test reads that file through `PDFCRAFT_EIDAS_REVOCATION_REPORT`, parses the v1 schema and verifies that the qualification stays `Indeterminate`.

Example (WSL Ubuntu):

```sh
cd /mnt/c/Users/User/Documents/GitHub/pdfcraft-signatures
PYTHONDONTWRITEBYTECODE=1 python3 tools/eidas_revocation_report.py \
  ~/pdfcraft-eidas-evidence/btrust-embedded-certs.pem \
  ~/pdfcraft-eidas-evidence/btrust-operational.crl \
  ~/pdfcraft-eidas-evidence/btrust-ocsp-response.der \
  2026-10-17T20:45:00Z > ~/pdfcraft-eidas-evidence/btrust-revocation-report-v1.json
source ~/.cargo/env
PDFCRAFT_EIDAS_REVOCATION_REPORT=$HOME/pdfcraft-eidas-evidence/btrust-revocation-report-v1.json \
  CARGO_TARGET_DIR=/home/yanakiev/pdfcraft-windows-build-target \
  cargo test --offline --locked -p pdfcraft-sign --lib -- external_python_evidence_report_remains_indeterminate
```

This is a verified offline integration test, not independent authentication of signing time or issuer path. The report and private certificate material are not committed. The Rust test skips the external fixture if the environment variable is absent; for the documented acceptance run the variable was explicitly set.
