# GitHub CI remediation — 2026-10-19

Scope: unofficial Yanakiev432 PdfCraft fork; no modification of the upstream repository.

## Findings

The initial fork PR GitHub Actions run had independent failures in the inherited CI. The Ubuntu formatting check detected unformatted Rust source in `crates/sign/src/lib.rs`, `qualification.rs`, `windows.rs`, and `crates/ui-egui/src/lib.rs`. Its `cargo-deny` action reported a wildcard (missing version requirement) for the first-party Git dependency `craft-signing-core`, an unapproved Git source in `deny.toml`, and RUSTSEC-2024-0436 for `paste`, transitively pulled by `cryptoki 0.10.1`.

## Remediation applied

1. Pin the first-party signer dependency to **both** a strict package version `=0.1.0` and exact immutable Git revision `a33e111`. Allow only this reviewed Git source in `deny.toml` while continuing to deny all other unknown Git dependencies.
2. Upgrade `cryptoki 0.10.1` to `=0.12.1`, `cryptoki-sys 0.4.0` to `0.5.0`, and `secrecy 0.8.0` to `0.10.3`. `paste 1.0.15` disappears from Cargo.lock. Upstream `cryptoki 0.12.0` removed `paste` (PR #347), and `0.12.1` fixes the out-of-bounds mechanism attribute read (RUSTSEC-2026-0286). No RustSec suppression or exception was added.
3. Update five PKCS#11 context initializations to the new `CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)` API. This preserves OS-managed locking but has *not* been hardware-tested with a physical signing token after the version change.
4. Apply `rustfmt` only to the four files flagged by the upstream formatting check (plus the PKCS#11 API file).

## Measured local gates

- WSL `cargo test --locked -p pdfcraft-sign --offline`: exit 0 (all tests passed, including the PDF set 52/52).
- WSL `cargo check --locked --target x86_64-pc-windows-gnu -p pdfcraft --offline`: exit 0.
- Windows `cargo fmt --all -- --check`: exit 0.
- `git diff --check`: exit 0.
- Cargo.lock has no `paste` package following upgrade.
- Real hardware B-Trust signing via upgraded PKCS#11 bridge: **not repeated**, PIN never accessed.

## Remaining verification

Only a fresh GitHub Actions run can confirm that the inherited workflow's source, version and advisory checks now pass. The fork PR auto-merges into a newer upstream main during its pull-request CI; this may introduce further independent regressions not observable from the local branch. The QES-specific push workflow uses exact committed source, read-only GitHub token permissions, no release/signing secrets and no artifact publishing.

Sources: https://github.com/parallaxsecond/rust-cryptoki/blob/main/CHANGELOG.md ; https://rustsec.org/advisories/RUSTSEC-2026-0286.html ; https://rustsec.org/advisories/RUSTSEC-2024-0436.html .
