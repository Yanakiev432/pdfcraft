# PdfCraft ↔ Craft Signer .NET detached CMS interoperability QA

**Date:** 2026-11-13
**Status:** isolated source-level integration QA, not a production installation.

## Evidence fixture

The test takes only three non-secret files from the developer-signed Craft Signer **0.2.2-qa** package, generated on the authorized Lenovo:

- `ModuleV2/Package/manifest.json`
- `ModuleV2/Package/manifest.p7s` (detached CMS)
- `ModuleV2/Package/publisher.cer` (public certificate)

Manifest SHA-256: `F8C5257D1F363E5ECAF255FBB891CA4C8593C9B69D8817D2B92D266F984415C1`.

The real .NET package's signed manifest contains the exact three worker hashes. This QA does not export or use the publisher private key, register a live module, add a Windows trusted root or connect to a hardware signing token.

## Issue and fix

The initial independent Rust verifier in `pdfcraft-sign::craft_signer_client` required a `messageDigest` signed attribute in every detached CMS signature. The signed .NET 8 `SignedCms` manifest was a valid *id-data* detached signature **without signedAttrs**. As permitted by CMS rules, the signature covers the content digest directly. Therefore the initial Rust client incorrectly failed closed, even though the .NET catalog checks passed.

The verifier now distinguishes both cases:

1. With `signedAttrs`, require the authenticated `messageDigest` attribute to equal the exact SHA-256 of the manifest.
2. Without `signedAttrs`, allow only the directly signed content digest path; never accept an inconsistent attribute.
3. In both cases, require one signer, SHA-256, the exact embedded publisher certificate, the independently approved public-key identity, current certificate dates, detached `id-data`, and successful cryptographic signature verification.

The independent `authenticate_signed_manifest` routine is shared by production `approved_broker()` and the opt-in test; this avoids a separate, weaker test-only parser.

## Executable interoperability test

Run on the authorized Windows developer machine:

```powershell
$env:CRAFT_SIGNER_DOTNET_CMS_QA_DIR = 'C:\Users\User\Documents\GitHub\craft-signer-installer-v022-qa-20261113\ModuleV2\Package'
cargo test -p pdfcraft-sign dotnet_signed_catalog_matches_independent_parser --lib --locked --offline -- --ignored --nocapture
```

**PASS**, exit 0: independent Rust verification of the exact .NET-authored catalog, including rejection of altered manifest bytes, signature bytes, public certificate bytes and wrong public-key fingerprint.

Ordinary test runs skip the fixture-dependent test because neither signed package nor any keys belong in source control; the test is explicitly marked `#[ignore]` and cannot silently count as covered in default CI.

## Release status

Craft Signer 0.2.2 is a locally Authenticode-signed developer preview, not publicly Windows-trusted. The prior 0.2.1 signed bundle remains unmodified. The new module is not installed in the live per-user extension directory and no publisher or DSS policy has been created there.

Pending full acceptance: explicit owner approval in the native installer UI, an installed module, pinned HTTPS EU DSS setup, live B-Trust PDF checks through both PdfCraft CLI and GUI, and first-party host support for WordCraft/GridCraft.
