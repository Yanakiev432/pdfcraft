# PDFCraft v0.18.2 — guarded PAdES / EU DSS QA rebase

Date: 2026-11-08.
Repo: Yanakiev432/pdfcraft.
QA branch: qa/pades-dss-upstream-v0182-20261108.
Upstream base: storyTold PDFCraft v0.18.2, git commit 7faa4f35cefb0dea04137ec475bdc770945c22cd.

## Current upstream source signature support

The native pdfcraft-sign crate already handles incremental PDF signing, PAdES-B/CMS, visible PDF signature fields, Windows store identities, and mechanisms for RFC 3161 timestamps and /DSS evidence. These source capabilities alone do not establish qualified signature status.

The older specialized fork contained a verify-qes CLI command, local EU DSS adapter, opt-in GUI Signatures-panel button, and independent evidence gates. This legacy integration was NOT contained in the clean v0.18.2 checkout.

## Historical independent B-Trust QES evidence — retained privately on Lenovo

Two archived EU DSS 6.5.1 local reports were inspected without exporting personal certificate details:
- 2026-10-18: PdfCraft-DSS-local/evidence/dss-validation-20261018.json
- 2026-10-23: PdfCraft-DSS-local/validation-20261023/independent-dss-response.json

Both reports contain one valid PAdES-BASELINE-B signature, TOTAL_PASSED, QESig, with BG/EU Trusted List checks. Both are historical, document-specific reports; neither proves live validation on 2026-11-08 nor qualified status of an arbitrary PDF. The older signed PDF in Windows Temp is absent. The older PAdES-B report does not establish independently trusted RFC 3161 time, B-T, B-LT or B-LTA.

When checked, localhost DSS ports 18080 and 8080 were NOT listening. Nothing was uploaded to an external DSS server.

## QA rebase

The new v0.18.2 branch includes the standalone Python local validator and PAdES-profile gate plus offline regression tests. The headless CLI is being extended with this explicit read-only action:

    pdfcraft-cli verify-qes signed.pdf --python PATH [--dss-port 18080|8080]

The CLI permits only pinned loopback endpoints. It verifies independent DSS schema, PDF SHA-256 and strict QESig / TOTAL_PASSED outcome, and fails closed. It does not create a signature, acquire keys, prompt for PIN, or modify trust settings.

Python adapter additionally refuses network redirection and OS proxy routing, does not contact public DSS services, and cannot infer qualified status from native PDF metadata. Profile gate requires explicit independent validation and never interprets B as T/LT/LTA.

Initial Python regression on Lenovo: 10 of 10 tests PASS. Windows Cargo check for the rebased CLI completed PASS on 2026-11-08 with the pinned upstream craft-libs dependency fetched. No production EXE was changed.

## Blocking gates

1. Complete current-source Windows CLI build and module-specific unit tests.
2. Port the legacy optional DSS button to the new GUI component tree and verify it with live interaction, including cancellation and network change.
3. Re-enable the local DSS service through a reviewed process and validate a currently available PDF, bound to SHA-256.
4. Real B-Trust provider acceptance requires the owner present for the native PIN dialog; no unattended hardware operations.
5. PAdES-B-T requires trusted timestamp; B-LT/LTA require independently verified and time-relevant revocation/evidence and archival maintenance.
6. Build signed MSI/EXE with a trusted code-signing certificate distinct from the personal QES.
7. Do not replace production apps, merge main or publish releases without approval.

PDFCraft uses PAdES inside PDF. WordCraft/GridCraft native OPC XMLDSig and external XAdES/ASiC-S are distinct formats.

## E. Opt-in Signatures panel GUI port (QA only)

A separate source-only migration from the legacy UI has been staged in the new v0.18.2 module structure:
- crates/ui-egui/src/dss_local.rs: asynchronous independent EU DSS state and SHA-256/mtime/length binding, with test-only state regressions.
- crates/ui-egui/src/lib.rs and src/app.rs: initialize app-local DSS status independently from PdfCraft native signature status.
- crates/ui-egui/src/panels/right.rs: add a clearly opt-in Check QES with local EU DSS control beneath native Validate all.
- crates/ui-egui/Cargo.toml: direct SHA2 dependency for file-fingerprint integrity.

The GUI route checks that the PDF was saved and unmodified, does not open any PIN/Windows certificate UI, does not sign, and does not alter the native trust result. The endpoint is pinned to 127.0.0.1:18080 and proxy/redirect refusal remains in the Python adapter. On a changed document, any prior local DSS validation is not reused.

Windows cargo check -p pdfcraft-ui-egui completed PASS on 2026-11-08. Actual desktop GUI click tests and live local-DSS validation are still outstanding. It does NOT modify the installed product, release, or upstream main branch.


## F. Successful compilation evidence

- Cargo check of pdfcraft-cli, --no-default-features, Windows x64: PASS. Full log and machine-readable receipt in PDFCraft-PAdES-QA-20261108 on Lenovo; no B-Trust key used.
- Cargo check of pdfcraft-ui-egui with new opt-in DSS Signatures panel control, Windows x64: PASS. Full log and machine-readable receipt in the same local QA folder.
- Python standalone DSS validator and profile gate unit tests: 10/10 PASS.
- Tests using a real, currently saved B-Trust signed PDF have not been rerun because the historical Temp PDF is no longer available and the local DSS service is not running.
- Release signer trust, production MSI and interactive GUI approval remain NO-GO.


## G. Security hardening: no arbitrary validation adapter (2026-11-08)

Security review found a high-impact fake QES PASS scenario in the initial rebase: the CLI accepted any caller-supplied Python adapter path. A malicious script could fabricate a valid-looking JSON report with the correct PDF SHA-256 and falsely assert QESig/TOTAL_PASSED without calling DSS.

This is now blocked in the QA source: both CLI and GUI **embed the audited Python adapter at Rust compile time**, execute it using Python isolation (-I -c), ignore PDFCRAFT_DSS_ADAPTER and refuse external --adapter overrides. The trusted script is no longer loaded from a user-selected path at runtime. The standalone manual PowerShell helper checks its local adapter SHA-256 against a hardcoded pinned digest before running. All endpoints remain fixed to explicit 127.0.0.1 loopback ports and disable proxy/redirect routing.

The result is a more defensible local validator boundary, but QES qualification still depends on the integrity of the local DSS server and EU Trusted List evaluation, not a self-issued certificate or native PDF metadata. A production release also requires a trusted installer publisher and full GUI acceptance.
