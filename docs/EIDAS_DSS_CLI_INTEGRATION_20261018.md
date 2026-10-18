# PdfCraft CLI — independent local EU DSS verification

The opt-in `pdfcraft-cli verify-qes` command delegates to the existing Python `tools/eidas_dss_local_verify.py` adapter and returns its machine-readable independent verdict. It does not require a public cloud validator and never enables remote validation implicitly.

Windows example (run from the repository root):
```powershell
.\target\debug\pdfcraft-cli.exe verify-qes "C:\Users\User\AppData\Local\Temp\pdfcraft-btrust-real-sign-20261017.pdf" --adapter ".\tools\eidas_dss_local_verify.py" --python "C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe"
```

Precondition: the separately installed official DSS 6.5.1 Tomcat webapp is running at `http://127.0.0.1:8080`, bound only to the loopback interface. This is a locally administered service with its own online trust-list/OCSP/CRL retrieval.

The CLI requires the operator to provide the PDF path, adapter script and Python interpreter explicitly. It launches Python with isolated mode `-I`, strips the adapter's optional endpoint override from the environment, rejects missing paths and invalid JSON schemas, and propagates validation failure with a nonzero exit status. The Python adapter restricts the destination to a literal loopback address, disables proxies and redirects, and does not expose the full private DSS diagnostic report by default.

This integration reports `independent_dss_qes_pass` separately from `native_qes_pass`; it is **not** a native Rust trust-list engine, a trusted signing-time proof, or a PAdES-LT/LTA upgrader. The CLI does not automatically validate files merely because they are opened or edited. No production signing or graphical UI controls are changed here.

## Executed acceptance

- `cargo check -p pdfcraft-cli --offline`: PASS.
- `cargo build -p pdfcraft-cli --offline`: PASS.
- Real B-Trust PDF via `target/debug/pdfcraft-cli.exe verify-qes`: exit 0, `TOTAL_PASSED`, `QESig`, `independent_dss_qes_pass=true` at `2026-10-18T20:36:43Z`; PDF SHA-256 `3016d0e0cbd7f72fa7dbc4c29685f714176d978f2c300f022c3d617d7abc9c9a`.
- Rust `qes::tests`: 2/2 PASS.
- Python `test_eidas_*.py`: 74/74 PASS.
- All sensitive full reports remain outside Git.

Remaining product gates: desktop Signatures panel wiring; long-term PAdES-LT/LTA issuance and preservation with trusted timestamps and authenticated, time-valid revocation evidence; release build/installer and end-to-end GUI acceptance. Do not claim these gates passed based on CLI validation alone.

## Additional real-file negative acceptance (2026-10-18)

A disposable copy of the original B-Trust PDF was modified by XORing one byte at offset 100, then passed to the same local DSS Python adapter. The validator raised `ValueError: DSS single-signature acceptance criteria not met`, returned exit code 1, and **did not** emit a QES PASS. The disposable PDF was deleted; the original file remained unchanged. This test demonstrates rejection of that specific tampering case; it is not exhaustive adversarial PDF fuzzing.
