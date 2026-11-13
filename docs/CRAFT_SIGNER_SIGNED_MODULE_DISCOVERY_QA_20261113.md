# PdfCraft: signed Craft Signer 0.2.2 module discovery — isolated acceptance

Date: 2026-11-13
Status: **source integration QA, not installation, activation, signing or official release**.
Branch: `qa/craft-signer-signed-module-fixture-v022-20261113`

## Why this gate exists

Verification of a detached CMS document alone does not establish that
a PdfCraft host can securely discover an installed, independently updated module.
The host must authenticate the *exact registered release*, verify the local
developer publisher approval **before** launching code, and hash the chosen
broker executable to match the signed module manifest.

The QA refactor exposes `approved_broker_under(root)` internally. The
ordinary production `approved_broker()` still obtains its fixed per-user
`LOCALAPPDATA/Craft/Extensions` root and calls that same function. There is
**no runtime environment override** enabling the application to use a fake
module root or bypass the owner's approval.

## Real signed 0.2.2 fixture

The ignored opt-in Rust test `dotnet_signed_module_registration_is_accepted_only_when_intact`
reads the actual developer-signed 0.2.2 QA package components:

* `ModuleV2/Package/manifest.json`
* `ModuleV2/Package/manifest.p7s`
* `ModuleV2/Package/publisher.cer` (public only)
* `ModuleV2/Broker/dist-local/CraftSignerBroker.exe`
* `Bundles/wordcraft-cli.exe` and `Bundles/gridcraft-cli.exe`

The publisher SHA-256 is computed independently from the X.509 public
SubjectPublicKeyInfo via OpenSSL and supplied to the test using
`CRAFT_SIGNER_PUBLISHER_SPKI_SHA256`. Only a randomly created
`tempfile` directory receives the temporary policy, `current.json`
and copied signed workers. No live policy file is created.

Run on an authorized Windows developer host with the signed local fixture:

```powershell
$env:CRAFT_SIGNER_DOTNET_V022_ROOT = '<signed-signer-v022-source-root>'
$env:CRAFT_SIGNER_PUBLISHER_SPKI_SHA256 = '<64-hex-SHA256-of-public-SPKI>'
cargo test -p pdfcraft-sign dotnet_signed_module_registration_is_accepted_only_when_intact --lib --locked --offline -- --ignored --nocapture
```

## Results and exclusions

**PASS**, one full signed-module discovery test, exit code 0:

* Accepted the exact .NET detached CMS 0.2.2 signed catalog and publisher
  SPKI pin, versioned release registration, required command list, broker file
  SHA-256 and locked broker path.
* Rejected a changed release directory in `current.json`.
* Rejected a changed publisher public key pin.
* Rejected one modified byte of the executable copied into the disposable release.
* The temporary module root is deleted after the test. The original signed
  package and live Craft installations are unchanged.

The C# publisher private key was never used or exported. No broker was
**executed** in this test, and no PIN, HTTPS DSS service, QES assertion,
official GUI integration or hardware token was involved.

Remaining true end-to-end gate: owner explicitly approves the module's public
publisher key through the native installer, installs the exact signed release,
configures a certificate-pinned HTTPS DSS instance, and validates a saved
B-Trust PDF through both PdfCraft CLI and GUI. WordCraft and GridCraft still
need the new first-party versioned command-provider hook to replace their
incompatible legacy fixed-worker extension slot.
