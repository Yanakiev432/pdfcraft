# PdfCraft Signatures panel — opt-in local EU DSS integration

The desktop Signatures panel now includes **Check QES with local EU DSS**, separate from **Validate all** (the native validation flow). It does not silently upgrade the native signature status. The check is asynchronous and only runs on a saved, unchanged PDF with a local filesystem path. Results appear in the panel as **Independent EU DSS: QES PASS** or **No QES PASS**, never as an unconditional native validation verdict.

The administrator must explicitly configure two environment variables before starting the desktop application:

```powershell
$env:PDFCRAFT_DSS_PYTHON = 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe'
$env:PDFCRAFT_DSS_ADAPTER = 'C:\Users\User\Documents\GitHub\pdfcraft-signatures\tools\eidas_dss_local_verify.py'
```

The separate local DSS 6.5.1 service must be listening at `http://127.0.0.1:8080` on the Windows machine. The adapter refuses non-loopback endpoints, proxy use and HTTP redirects. The GUI launches Python in isolated mode (`-I`), strips the optional endpoint override, and independently compares the SHA-256 digest of the file to the digest reported by the adapter. The GUI displays a deliberately PII-free summary rather than full diagnostic reports.

The UI currently supports only the one-signature acceptance gate in the Python adapter; multi-signature reports are not classified as QES PASS. This check is independent and does not implement PAdES-LT/LTA issuance, archival evidence or signing-time proof.

**Verification:** `cargo check -p pdfcraft-ui-egui --offline` succeeded in WSL Ubuntu 24.04 with an isolated Linux Cargo target directory on 2026-10-19. A Windows build attempt was blocked by the device's Application Control policy (os error 4551) while executing a Rust dependency build script. No policy changes were made. Full Windows GUI runtime acceptance remains pending.

## Continuation: stale-result invalidation and Windows build gate (2026-10-19)

The panel stores the PDF file size and last-modified time immediately after independently comparing its SHA-256 digest with the DSS report. A later save or replacement that changes either file attribute invalidates the previously displayed result and requests a fresh QES check. The existing unsaved-edit guard remains in effect. This lightweight post-validation guard is **not** a cryptographic assertion that timestamps and file size cannot be forged; the actual SHA-256 comparison occurs during each opt-in validation.

Acceptance completed locally in WSL Ubuntu 24.04:

- `cargo check -p pdfcraft-ui-egui --offline`: exit code 0.
- `cargo test -p pdfcraft-ui-egui --lib --offline dss_local::tests`: 3 passed, 0 failed (includes the new saved-PDF replacement regression).
- `cargo fmt --all` and `git diff --check`: passed; unrelated format-only changes were reverted.

The direct Windows `cargo check -p pdfcraft-ui-egui --offline` remains blocked by Windows Application Control, error 4551, on a generated Rust `winit` build script. Existing dependency errors from that run do not qualify as product-code regressions until compilation can proceed in an authorized build environment. The blocked Windows development build is not a substitute for a Windows GUI smoke test.

For release signing, do not use a document-signing personal QES certificate as a code-signing credential. Use a certificate explicitly issued for Code Signing with an appropriate, policy-trusted publisher identity and verify its chain and timestamp, or an authorized narrowly scoped build environment. Signing the final EXE/MSI cannot itself authorize ephemeral, unsigned Rust build-script executables. No Windows security policy was weakened or disabled.
