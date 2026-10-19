# PdfCraft / WordCraft / GridCraft reusable signing module — integration gate

2026-10-19

The actual upstream applications are `storytold/wordcraft` and `storytold/gridcraft`. The latter is named **GridCraft**, not CellCraft.

Reusable crate: `https://github.com/Yanakiev432/craft-signing-core`, draft [PR #1](https://github.com/Yanakiev432/craft-signing-core/pull/1), head `a33e111`.

This PdfCraft branch pins precisely `a33e111` in `crates/sign/Cargo.toml` and `Cargo.lock`, and re-exports the host-neutral contract through `pdfcraft_sign::providers` on every platform. The dependency contains native certificate/Windows CNG capabilities behind their existing Windows cfg gate; Office format metadata is platform-neutral.

**Verified gates:**
- Shared-core WSL offline tests: 6 passed / 0 failed.
- Shared-core WSL Windows GNU cross-target check: PASS.
- PdfCraft core full `cargo test -p pdfcraft-sign --offline`: PASS, 0 failures.
- PdfCraft Windows desktop `cargo check -p pdfcraft --target x86_64-pc-windows-gnu --offline`: PASS.
- PdfCraft dedicated format mismatch test: 1 passed / 0 failed.

**Scope**: This is true source dependency integration for common provider/format contracts, not yet completed WordCraft or GridCraft application integration. A PDF/CMS signature cannot be trivially substituted for an Office XMLDSig signed OPC package. WordCraft and GridCraft each need separate package-signing and verification code, trusted Office interop tests, and explicit pinning of a reviewed shared-core release. Their respective upstream repositories were not changed.

**QES boundary:** No Office qualified electronic signature has been produced or independently certified. Certificate qualification, historical trust state, and Office package integrity require distinct verification.
