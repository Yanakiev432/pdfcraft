# SignPath Foundation — Craft fork readiness (2026-10-20)

Status: **APPLICATION NOT SUBMITTED; APPROVAL NOT RECEIVED; TRUSTED RELEASE NO-GO**.

## Public project
- Fork: https://github.com/Yanakiev432/pdfcraft
- Upstream: https://github.com/storytold/pdfcraft
- Signing component: https://github.com/Yanakiev432/craft-signing-core
- Engineering process: https://github.com/Yanakiev432/craft-fork-method

## Verified local engineering evidence
- Existing upstream Windows installers for PdfCraft 0.9.0, WordCraft 0.8.0 and GridCraft 0.8.0 report Authenticode Valid, publisher Learning Machines Inc. This does not grant use of upstream publisher identity for fork builds.
- Current fork debug pdfcraft-cli.exe is NotSigned.
- eIDAS Python tests: 78/78 PASS on 2026-10-20 using uv with cryptography.
- Synthetic OPC DOCX/XLSX sign/verify/tamper tests: 2/2 PASS.
- Signed test PDF has a recorded local EU DSS QESig/TOTAL_PASSED PAdES-BASELINE-B acceptance; not a code-signing credential.
- No trusted fork MSI build, installation or Smart App Control release acceptance demonstrated.

## Application prerequisites and constraints
1. Verify fork eligibility under https://signpath.org/terms.html, including requirements applying to modified forks of signed upstream projects.
2. Confirm upstream branding, trademark, redistribution rights and independent fork identity.
3. Obtain explicit SignPath Foundation approval, project onboarding and authorized signer/release roles.
4. Agree on supported trusted build provenance. A GitHub-hosted build may require a specific user decision because the existing CI policy is local-first.
5. Freeze reviewed source commit, lockfile, dependencies, license attribution, release identity and repeatable build inputs.
6. Sign EXE, DLL and MSI under approved publisher identity and RFC3161 timestamp. Independently check Authenticode, EKU, certificate chain, artifact hashes and timestamp.
7. Run clean Windows install/uninstall/rollback, GUI smoke and Smart App Control enforcement tests without disabling system protections.

## Security boundaries
Do not use a B-Trust document QES certificate as a substitute for a Code Signing EKU. Do not disable WDAC/Smart App Control, add self-signed roots, export token keys or handle a PIN. Never label a draft or unsigned build production-ready.

## Release decision
- Code-signed EXE: NO-GO pending approved signing identity and signed artifact.
- Trusted MSI: NO-GO pending signed MSI, independent validation and clean installation acceptance.
- No external application or approval is claimed by this document.
