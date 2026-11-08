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
- 0.19.0 Windows cargo check: **PASS for both pdfcraft-cli and pdfcraft-ui-egui** on the pinned upstream dependency graph; 0.19.0 Rust targeted unit tests remain separately gated.
- Real owner-present B-Trust QES signing with provider-managed PIN: **not attempted in this QA work**.
- Local EC DSS 6.5.1 verification of an **already signed existing PDF**: **TOTAL_PASSED / QESig** as a document-specific local validation result; no hardware signing or PIN. A temporary one-byte altered clone of the same real signed PDF was independently classified **TOTAL_FAILED**, and the original PDF SHA-256 was unchanged. Personal original and full validation reports were kept on the Lenovo, not published to GitHub. This establishes independent validation behavior for this document only, not trusted production GUI acceptance.
- PAdES B-T / LT / LTA acceptances: **not established**. A QES-level result for PAdES-B is not an archival timestamp.
- Code-signing and trusted MSI publishing: **not implemented in this QA branch**.

The installed official 0.19.0 MSI was separately verified and passed basic GUI start-up; it **does not include these custom QA changes**. Never claim this module is installed or QES accepted in that publicly signed binary.

## Safety and deployment

No main merge, no installer replacement, no production changes, no GPU workloads, no API charges. Keep source, signed PDF and independent validator reports local and preserve input document SHA-256. Any owner-present hardware test requires explicit Windows certificate selection and the manufacturer's native PIN UI. Qualified result must be checked against a current independent validator and trusted lists, not inferred from a crypto-only pass.


## Verification evidence and limitations (2026-11-08)

1. Pinned upstream tag and clean local checkout: 8c572792d6760bdc903d6f9a032e3e38e8f71cb8.
2. File-for-file GitHub QA branch parity: 14/14 uploaded source files identical to the local Windows worktree before Cargo.lock update. The lockfile contains direct sha2 v0.10.9 entries for both app packages.
3. Python evaluator/profile regression: **10/10 PASS** on v0.19.0.
4. Windows Cargo check for both CLI and GUI: **PASS**.
5. Live local independent DSS 6.5.1 result for a locally saved document previously signed with a qualified certificate: **QESig + TOTAL_PASSED**. The original was not modified and no PIN or private key was used.
6. Same real signed document, altered **ephemeral one-byte clone**: independent DSS **TOTAL_FAILED**; client rejected it; clone automatically deleted after the test.
7. Self-issued or altered synthetic PDF cases did not yield a qualified PASS. Invalidating inputs are explicitly refused; a missing local DSS service is also fail-closed, not treated as a crypto validation.
8. Targeted Rust v0.19.0 tests: initial --offline test harness could not resolve git dependency craft-docpath, so did not execute any test. An online locked dependency resolution and Rust regression is a separate pass gate, not inferred from the successful cargo checks.

Private document hashes and raw qualified validation reports are stored ONLY on the authorized Lenovo under CraftUpdates/Signing-Rebase-20261106/PDFCraft-PAdES-QA-20261108/*.private.json, and are deliberately excluded from public GitHub.

The installed official publisher-signed v0.19.0 application and its Desktop/crafts shortcut remain unchanged. Its GUI has NOT been replaced with this QA feature; successful source compilation is not an installation.


## I. Compiled native Windows CLI acceptance — 2026-11-08

The v0.19.0 QA source tree has passed all of these as separate actual executions on Lenovo:

- Rust CLI focused unit tests: **4/4 PASS**, zero failures.
- Windows CLI binary build (cargo build --locked -p pdfcraft-cli --no-default-features): **PASS**.
- CLI compiled-binary end-to-end independent DSS check: **4/4 PASS** using native pdfcraft-cli.exe and local EC DSS 6.5.1:
  - Already existing qualified signed PDF: QES accepted, DSS QESig / TOTAL_PASSED.
  - Self-issued test certificate: QES rejected.
  - Modified temporary byte clone of the genuinely signed PDF: QES rejected.
  - Malicious external --adapter injection attempt: rejected before verification.
- The original signed PDF remained bytewise unchanged, and temporary altered clone was deleted. No private keys or PIN were accessed; no confidential PDF uploaded.
- The combined GUI Rust unit suite remains a separate gate, not implied by successful CLI tests or cargo check.
- No published trust-signed installer, no change to installed official PDFCraft v0.19.0 or the desktop shortcut.

QA-only local CLI build and original-document-private receipts live under Documents/CraftUpdates/Signing-Rebase-20261106. Do not publish personal signed PDF bytes, filenames or private receipts in GitHub.


## J. Native GUI Rust test acceptance — 2026-11-08

The initially interrupted Windows GUI test compilation was retried incrementally, then completed **PASS**:

- cargo test --locked -p pdfcraft-ui-egui --lib dss_local::tests -j 2: **5/5 PASS**.
- Dirty document is not validated against its previously saved PDF bytes.
- A changed PDF invalidates prior QES verdict even when an attacker restores the original file length and modification time.
- No QES claim is present on initial GUI state.
- Embedded immutable DSS validator is present, and arbitrary external Python adapter substitution is rejected by design.
- Together with the four CLI Rust tests and ten Python tests, the v0.19.0 targeted source regression suite is **19/19 PASS**.

A full desktop GUI binary build and separate portable UI-control acceptance are distinct gates. The installed official PDFCraft v0.19.0 remains untouched; the QA build is not a public code-signed release. The owner's Desktop/crafts shortcuts still point exclusively to verified official installed Craft versions.
