# PdfCraft Windows release trust gate (2026-10-19)

## Packaging state

The project's upstream `packaging/windows/package.ps1` supports WiX v5 MSI and portable ZIP and delegates signing to `sign.ps1`. When signing credentials are not set, `sign.ps1` **normally prints a warning and exits 0**, leaving unsigned artifacts. That is acceptable only for local *development*, never a claim of a trusted production release.

This fork adds `packaging/windows/assert-trusted-release.ps1` and an explicit `-RequireTrustedRelease` switch to `package.ps1`. When switched on, the package process must reject an EXE, CLI or MSI without a valid Authenticode publisher signature, the Code Signing EKU, RSA publisher key and timestamp signer. It checks release files read-only: no self-signed certificate imports, Windows security policy edits or trust-store mutations.

```powershell
# Run only in a legitimate authorized Windows build environment with
# WiX, Windows SDK, MSVC toolchain and publisher credentials configured.
& .\packaging\windows\package.ps1 -Arch x64 -RequireTrustedRelease
```

Local negative acceptance: `assert-trusted-release.ps1` called on unsigned PdfCraft QES Preview produced `CODE_SIGNING_NO_GO ... NotSigned` and process exit 1. Static PowerShell parsing succeeded for both edited packaging scripts.

## Blockers to a trusted installer

- The Lenovo certificate stores did not contain a checked usable Code Signing EKU certificate; the B-Trust **document QES** is not a Code Signing credential.
- `wix` and `signtool` were absent from the observed PATH; installation of these is not equivalent to obtaining a trusted publisher.
- No signed MSI has been built, independently signature-verified, installed, uninstalled and tested through Smart App Control as a release.
- Upstream/PdfCraft branding and distribution rights need explicit review; a clone with `origin` pointing at upstream does not automatically satisfy formal fork/maintenance provenance rules.

Possible authorized trusted publisher routes:

1. A publisher code-signing identity issued under an accepted CA/Artifact Signing arrangement (may cost money), with verified chain and timestamp, signed PE/MSI, and independent SAC enforcement testing.
2. For an eligible open-source project, SignPath Foundation approval plus reproducible trusted build provenance and release approval. For a *modified upstream fork* SignPath's policy additionally requires upstream signed builds and an identifiable fork, so eligibility is **not established** here.
3. Microsoft Store MSIX distribution, subject to account and Store certification, where Microsoft handles signing. An MSI uploaded to the Store is not covered by the same automatic signing.

Microsoft documentation distinguishes Smart App Control and SmartScreen reputation: even a newly signed outside-Store binary may produce SmartScreen reputation warnings. A local Authenticode `Valid` check alone does not certify future SAC acceptance for every installed system.

Reference sources:
- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options
- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
- https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview
- https://signpath.org/terms.html

## Current release status

Unsigned portable user preview tested with Windows GUI: PASS. Authenticode: NotSigned. Trusted MSI release: **NO-GO**, pending a legitimate publisher/signing service, WiX and signing SDK and external approval. Do not disable or weaken Smart App Control.
