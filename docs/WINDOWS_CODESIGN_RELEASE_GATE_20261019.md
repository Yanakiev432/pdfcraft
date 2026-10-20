# Windows release-signing and deployment gate — PdfCraft signatures
Date: 2026-10-19

## Observed on Yanakiev-Lenovo
- Enforced Application Control/Smart App Control policy: `VerifiedAndReputableDesktop`, policy ID `27555.1000.240208`. Code Integrity event 3077 and Rust build-script launch error 4551 are reproducible.
- No currently valid certificate with private key and **Code Signing EKU** was located in the checked CurrentUser/My and LocalMachine/My stores.
- Installed `C:\Program Files\PdfCraft\pdfcraft.exe` is v0.8.0 and Authenticode `NotSigned`; Microsoft's reputation-based allowance for one binary is not authorization for another binary or a rebuilt variant.
- Source branch `feature/universal-signature-providers` passes Linux GUI checks and independent local DSS QES validation. The updated Windows GUI has **not** been installed.

## Release blocker: do not mistake a PDF QES for executable signing
A valid B-Trust document-signing certificate does not establish suitability for Authenticode Code Signing. Do not use its private key/PIN for arbitrary EXE/MSI signing, do not self-sign and silently change machine trust, and do not disable Smart App Control or modify WDAC policies to force a PASS. A signature on the finished executable would not authorize unsigned Rust `build-script-build` programs spawned *earlier* in a protected build environment.

## Safe release lane
1. Freeze an exact, reviewed source commit, lockfile, third-party attribution and release version; use a branded fork without assuming permission to redistribute upstream trademarks.
2. Build in a **separate, authorized** build environment whose administrator permits the build toolchain to execute its generated programs. Do not change the protection status of Yanakiev-Lenovo to force developer tools through.
3. Arrange trusted publisher signing for EXE, DLL and MSI artifacts (and any other binaries requiring signatures), with correct Code Signing EKU and RFC 3161 timestamp. Verify the **actual** signed files, certificate chain and SHA-256 digests.
4. Run a staged Windows GUI smoke test on a SAC-enforced machine, without changing the SAC policy: launch, open signed PDF, select correct signing identity, invoke only user-approved SafeNet authentication, validate independent DSS, negative/tampered-PDF handling and rollback.
5. Only after every gate passes, back up the existing installation and replace it atomically with the signed verified build, retaining installer and rollback metadata.

## Cost-free signing possibility — not yet obtained
SignPath Foundation advertises free code signing for qualifying open-source projects but requires an OSI-approved public project, source/build provenance, roles, approved trusted build system and additional conditions. In particular, modified forks of an upstream project have special eligibility conditions, including upstream signed releases. **We have not established that this fork is eligible, nor submitted or received approval.** Do not label a binary signed or production-ready on the strength of this option.

Official references:
- Microsoft Smart App Control: https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview
- Microsoft Smart App Control testing: https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control
- SignPath Foundation policy: https://signpath.org/terms.html
- SignPath Foundation OSS service: https://signpath.org/

## Current decision
Windows production deployment: **NO-GO** until authorized build, legitimate signing arrangement and SAC runtime tests exist.
Current safe user-facing option: `tools/verify-qes-local.ps1` read-only local DSS QES check for already signed PDFs. It is not the modified GUI.
