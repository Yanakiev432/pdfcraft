# PDFCraft v0.19.0 — independent PAdES/QES validation rebase (QA only)

Status: **QA source branch, not installed production feature**.

- Official upstream: storyTold/pdfcraft tag v0.19.0, immutable commit 8c572792d6760bdc903d6f9a032e3e38e8f71cb8.
- Owner's isolated GitHub branch: Yanakiev432/pdfcraft, qa/pades-dss-upstream-v0190-20261108.
- Clean separate Windows git worktree: Documents/GitHub/pdfcraft-qes-upstream-v0190-20261108.
- Previously audited source: QA rebase v0.18.2; CLI 4/4, GUI 5/5, Python 10/10; no external hardware key accessed.

## Purpose

PDFCraft uses embedded PAdES PDF signatures, **not** WordCraft/GridCraft XMLDSig or the separate XAdES ASiC-S container. This source-only QA extension introduces a separate, opt-in, independent European Commission DSS-qualified verification pathway. It does not acquire private keys, create signatures, or silently change the application's native PDF trust result.

The v0.19.0 CLI command is:

    pdfcraft-cli verify-qes signed.pdf --python PATH_TO_PYTHON_EXE [--dss-port 18080|8080]

The independent DSS validator is embedded at Rust compilation time, not loaded from a user-supplied Python file; the CLI rejects --adapter. Python is launched in isolated mode -I -c. DSS endpoint is pinned to 127.0.0.1 on explicit port 18080 or 8080; proxy use and redirects are disabled by the validator. The validator requires the DSS TOTAL_PASSED indication and QESig classification and binds the report to the input PDF SHA-256.

The GUI Signatures panel adds an opt-in Check QES with local EU DSS button. The GUI uses PDFCRAFT_DSS_PYTHON to specify an installed Python interpreter, with the same validator embedded in the application. It does not reuse a prior QES indication after the document changes; saved, unchanged PDF required. The UI does not display a QES PASS for unsigned or self-issued synthetic test signatures.

## Test gates

- 0.19.0 Python regression suite (tools/test_eidas_*.py): **10/10 PASS**.
- 0.19.0 Rust CLI and GUI compile and targeted tests: **pending**, must be checked against the 0.19.0 dependency graph, not copied from 0.18.2 receipts.
- Real owner-present B-Trust QES signing with provider-managed PIN: **not attempted in this QA work**.
- Real independent European Trusted Lists / revocation / QSCD validation for a current signed PDF: **not yet accepted on this version**.
- PAdES B-T / LT / LTA acceptances: **not established**. A QES-level result for PAdES-B is not an archival timestamp.
- Code-signing and trusted MSI publishing: **not implemented in this QA branch**.

The installed official 0.19.0 MSI was separately verified and passed basic GUI start-up; it **does not include these custom QA changes**. Never claim this module is installed or QES accepted in that publicly signed binary.

## Safety and deployment

No main merge, no installer replacement, no production changes, no GPU workloads, no API charges. Keep source, signed PDF and independent validator reports local and preserve input document SHA-256. Any owner-present hardware test requires explicit Windows certificate selection and the manufacturer's native PIN UI. Qualified result must be checked against a current independent validator and trusted lists, not inferred from a crypto-only pass.
