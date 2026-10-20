# B-Trust manual RFC3161 — one in-flight CMS signature without TSA API

**Developer capability, not an approved qualified release.** The BORICA service
request `SD1614999` may proceed independently. No BORICA authentication or
production TSA API is required to test this in-flight handoff.

## Two safe, distinct stages

- **Stage A (same running process):** `sign_with_timestamp` produces the CMS
  signature once and invokes `ManualTsaHandoff`. The authority writes
  `<session>.tsq` atomically with exclusive creation and waits for the reply.
  No original PDF, document content, private key, hardware PIN or credentials
  are transmitted.
- **Stage B (before timeout):** the human gets `<session>.tsr` from a provider
  with compatible terms (for example the official B-Trust nonprofit form:
  https://www.b-trust.bg/services/time-stamp-issue). The human saves the entire
  DER response to the session directory and **only then** creates
  `<session>.tsr.ready`.
  `ManualTsaHandoff` checks a real response file, maximum 4 MiB, then
  validates CMS signature, matching SHA-256 imprint, nonce, optional policy.
  The same signing call finishes embedding the token as the unsigned
  signature-timestamp attribute without calculating a second CMS signature.
  The final PDF's signed ByteRange is checked again before writing output.

The authority does not persist private signing material, alter system trust
stores, connect to an unauthorized TSA, or weaken Windows SAC/WDAC.

### Reproducible test-key command (PowerShell 7)

In an isolated folder with the repository checked out and a working Rust
toolchain, from the repo root:

```powershell
New-Item -ItemType Directory -Force -Path '.\tmp\manual-tsa-demo' | Out-Null
python .\tools\make_rfc3161_fixture.py --out '.\tmp\manual-unsigned.pdf'
$env:PDFCRAFT_TEST_PKCS12_PASSWORD = 'test'
cargo run --locked -p pdfcraft-sign --example rfc3161_manual_pades_bt -- `
  '.\tmp\manual-unsigned.pdf' `
  '.\tmp\manual-signed.pdf' '.\crates\sign\tests\data\rsa-aes.p12' `
  '.\tmp\manual-tsa-demo' 'example20261020a' 'D:20261020090000Z' 900
Remove-Item Env:PDFCRAFT_TEST_PKCS12_PASSWORD
```

The command **blocks** while waiting for the human to obtain a real response.
It must be run on the user machine, not a time-limited GitHub Action.
While it is waiting, from another console or the operating system's file
manager, use only a legally authorized provider:

1. Upload `tmp/manual-tsa-demo/example20261020a.tsq` **only** to the official
   website and download its `.tsr` response. Do not upload a PDF file.
2. Write a **fully downloaded and closed** response as
   `tmp/manual-tsa-demo/example20261020a.tsr`.
3. After the complete response is on disk, create the marker file:

```powershell
New-Item -ItemType File -Path '.\tmp\manual-tsa-demo\example20261020a.tsr.ready'
```

If the timeout expires, no output PDF is written. The TSQ remains as an
**orphan** for audit only: it must never be reused by a different signing
attempt. Use a fresh, non-colliding session ID instead of overwriting old
`.tsq` or `.tsr` files.

The CLI above opens a **disposable PKCS#12 software test key**. The reusable
`ManualTsaHandoff` struct can be used by a future user-authorized hardware
CNG/PKCS#11 signing flow, but this demo neither accesses a physical B-Trust
device nor proves that integration.

## Windows Current User CNG smart-card path (compiled but NOT physically accepted)

The native Windows example `crates/sign/examples/rfc3161_windows_manual_pades_bt.rs`
calls `pdfcraft_sign::windows::find` to obtain the exact Windows certificate-store
reference. It uses `PrivateKey::external`, preserving the private key inside
Windows CNG or its authorized smart-card driver. Any PIN confirmation is owned
entirely by the official provider UI. It neither accepts a PIN argument nor
places a PIN in source, environment or GitHub CI.

Obtain the exact SHA-256 reference **without opening the private key**:

```powershell
Get-ChildItem 'Cert:\CurrentUser\My' | ForEach-Object {
  [PSCustomObject]@{
    Subject = $_.Subject
    CertificateReference = 'windows:' + [Convert]::ToHexString(
      [Security.Cryptography.SHA256]::HashData($_.RawData)
    ).ToLowerInvariant()
  }
}
```

With a clean disposable unsigned test PDF and a selected certificate
reference from the listing, a human may run on the local Windows computer:

```powershell
cargo run --locked -p pdfcraft-sign --example rfc3161_windows_manual_pades_bt -- `
  '.\tmp\manual-unsigned.pdf' '.\tmp\manual-cng-candidate.pdf' `
  'windows:<SHA256_OF_SELECTED_CERTIFICATE_DER>' '.\tmp\manual-tsa-demo' `
  'windows20261020a' 'D:20261020090000Z' 900
```

This first invokes the genuine CNG certificate provider to sign once and
then retains the same process while the human obtains the exact TSR via the
provider's authorized manual channel. A fresh session name and new destination
are mandatory. **No one should execute the real-token path unattended or
provide a PIN through chat.** The GitHub CI can only verify that this bridge
**compiles**; it cannot validate a B-Trust hardware PIN interaction or grant
legal eIDAS qualification. The manual TSR still needs a qualified provider,
verified QTSA service status and independent EU DSS acceptance.

### Acceptance boundaries

- Open TSA works only as a **nonqualified** developer provider.
- B-Trust nonprofit form use depends on the site's published conditions and
  may need separate technical/identity authorization.
- RFC3161 integrity, CMS signature and nonce checks are not legal QTSA status.
- Only trustworthy EU LOTL/national Trusted Lists at token generation time
  and independent EU DSS verification of the final PDF can support a
  qualified PAdES-B-T verdict.
- **B-LT** requires validated cert/OCSP/CRL material in the signed PDF and
  DSS acceptance. **B-LTA** adds appropriately signed archive timestamps,
  long-term renewal and DSS acceptance.
- A timeout without complete TSR cannot be resumed after the original signer
  process exits. This is a one-shot design, not a crash-resumable transaction.

`ManualTsaHandoff` includes no-network tests: signed local synthetic
TimeStampResp positive round-trip, timeout/stale-session rejection, existing
TSR rejection and restricted session names. It preserves final release status
`NO_GO` until independent external acceptance gates pass.
