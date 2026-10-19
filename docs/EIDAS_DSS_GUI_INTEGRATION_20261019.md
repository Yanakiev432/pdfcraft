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
