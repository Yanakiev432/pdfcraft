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

    pdfcraft-cli verify-qes signed.pdf --adapter tools/eidas_dss_local_verify.py --python PATH [--dss-port 18080|8080]

The CLI permits only pinned loopback endpoints. It verifies independent DSS schema, PDF SHA-256 and strict QESig / TOTAL_PASSED outcome, and fails closed. It does not create a signature, acquire keys, prompt for PIN, or modify trust settings.

Python adapter additionally refuses network redirection and OS proxy routing, does not contact public DSS services, and cannot infer qualified status from native PDF metadata. Profile gate requires explicit independent validation and never interprets B as T/LT/LTA.

Initial Python regression on Lenovo: 10 of 10 tests PASS. Rust CLI Windows build is a separate acceptance gate. Do not claim its result until compilation completes.

## Blocking gates

1. Complete current-source Windows CLI build and module-specific unit tests.
2. Port the legacy optional DSS button to the new GUI component tree and verify it with live interaction, including cancellation and network change.
3. Re-enable the local DSS service through a reviewed process and validate a currently available PDF, bound to SHA-256.
4. Real B-Trust provider acceptance requires the owner present for the native PIN dialog; no unattended hardware operations.
5. PAdES-B-T requires trusted timestamp; B-LT/LTA require independently verified and time-relevant revocation/evidence and archival maintenance.
6. Build signed MSI/EXE with a trusted code-signing certificate distinct from the personal QES.
7. Do not replace production apps, merge main or publish releases without approval.

PDFCraft uses PAdES inside PDF. WordCraft/GridCraft native OPC XMLDSig and external XAdES/ASiC-S are distinct formats.
