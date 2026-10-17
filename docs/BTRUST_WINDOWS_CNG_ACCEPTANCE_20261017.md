# B-Trust Windows signing acceptance — 2026-10-17

## Scope and consent

A single, explicitly authorized hardware signing attempt was performed on the user's Windows machine. The user entered the PIN in the vendor-provided interface. PdfCraft did not collect, log, or store the PIN. No automated retry was performed. This record intentionally excludes personal certificate subject names, serial numbers, and PIN data.

## Environment

- Windows CurrentUser/My certificate store
- B-Trust USB smartcard with SafeNet Authentication Client 10.9
- Windows certificate provider metadata: `eToken Base Cryptographic Provider` (legacy CSP)
- Windows .NET exposed an `RSACng` key handle
- PdfCraft uses `rustls-cng`, acquiring a non-silent key handle for the vendor prompt
- PKCS#11 token slots reported `protected_authentication_path=false`; PKCS#11 protected-authentication signing path is not applicable to this setup

## Acceptance evidence

1. Selected certificate detected as usable in PdfCraft's silent Windows identity inventory: PASS.
2. One opt-in hardware signing attempt via Windows CNG and vendor PIN interface: PASS.
3. PdfCraft internal signed-PDF validation with the signing certificate as explicit trust anchor: `Valid`.
4. Independent Poppler `pdfinfo` PDF parse: PASS (PDF 1.7, 1 page, 25,582 bytes).
5. Independent OpenSSL `cms -verify -binary -noverify` over the exact PDF `/ByteRange` bytes: `CMS Verification successful` (exit 0).

Signed PDF location on test machine: `%LOCALAPPDATA%\Temp\pdfcraft-btrust-real-sign-20261017.pdf`.

Signed PDF SHA-256: `3016D0E0CBD7F72FA7DBC4C29685F714176D978F2C300F022C3D617D7ABC9C9A`.

## Limits

- OpenSSL `-noverify` confirms cryptographic integrity, not independent certificate-chain trust, revocation (OCSP/CRL), qualified-signature status, or PAdES-LT/LTA compliance.
- Adobe Acrobat signature-panel acceptance has not been checked.
- One successful signature is not a general compatibility guarantee for other tokens or driver versions.
- Hardware signing tests remain ignored by default and must not run in CI without separate authorization.