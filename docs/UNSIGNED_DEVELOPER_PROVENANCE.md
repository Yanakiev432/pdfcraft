# UNSIGNED development artifact provenance — NOT Windows code signing

This feature is a no-cost **technical preview** path after the 2026-10-21
SignPath Foundation application was declined for insufficient public
adoption/reputation. It is not a trusted Windows installer.

## Developer-only GitHub Actions job

`.github/workflows/unsigned-developer-artifact-attestation.yml`:
1. Uses an immutable source commit and pinned checkout/Rust toolchain.
2. Compiles PdfCraft x64 EXE and CLI with `cargo --locked --release`.
3. Confirms neither executable unexpectedly reports `Authenticode: Valid`.
4. Packages binaries, licenses, a complete SHA256 file manifest, and a
   clearly conspicuous `UNSIGNED-TEST-ONLY.txt` safety warning.
5. Uses pinned `actions/attest` to associate the exact ZIP SHA-256 with
   the source repository and build workflow in public Sigstore.
6. Uploads **only** a short-retention GitHub Actions **artifact** named
   `pdfcraft-UNSIGNED-DEVELOPER-ONLY-x64`, never a GitHub Release.
7. Does not make a QES signature, access B-Trust, import keys, request PIN,
   deploy a public installer, or call the SignPath Foundation signer.

### Independent verification

After authorized download of an Actions test ZIP to an isolated folder:

```powershell
gh attestation verify 'C:\path\to\pdfcraft-UNSIGNED-DEV-windows-x64.zip' -R Yanakiev432/pdfcraft
```

This checks build provenance against the GitHub repository and source
workflow. Inspect the embedded `build-manifest.json` and hashes. The
attestation does **not** make these EXE files trusted in Windows, because
Smart App Control evaluates an Authenticode identity/reputation independently.

**Do not disable SAC or WDAC to run the unsigned preview.** A blocked
test executable is a legitimate `SAC=REJECTED` result.

## Separate real trusted release

The reviewed `.github/workflows/release.yml` continues to include the
explicit failing `fail-closed-release-preflight`, and signed EXE/MSI
require a pre-approved publisher DER certificate SHA-256, Code Signing
EKU, actual Authenticode signer and trusted timestamp. SignPath
Foundation has **not** approved the free signing application.

The maintenance effort can grow documented public adoption and reapply
to Foundation. No paid provider or CA root is installed automatically.

## Qualified document signatures

An action-generated Sigstore attestation is not an eIDAS QTSA timestamp,
is not PAdES B-T/LT/LTA, is not Microsoft Office native XMLDSig
interoperability and cannot serve as an authorized B-Trust QES identity.

References:
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://cli.github.com/manual/gh_attestation_verify
- https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions
