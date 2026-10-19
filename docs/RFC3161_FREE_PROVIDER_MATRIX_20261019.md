# RFC 3161 provider selection — independent of BORICA (2026-10-19)

Scope: PdfCraft / Craft signing ecosystem. This is an engineering checkpoint, **not** an
eIDAS qualification declaration or a claim of PAdES-B-T/LT/LTA success.

## Verified provider policies

| Provider | RFC 3161 endpoint | Qualification status | Documented usage | Engineering treatment |
| --- | --- | --- | --- | --- |
| Open TSA (Germany) | `https://tsr.open-tsa.eu` | **Not eIDAS-qualified** (provider disclosure) | Free public endpoint for developers, researchers, NGOs and startups; project is MIT-licensed | **LIVE TEST**: synthetic imprint and fresh nonce; never trust as a qualified timestamp |
| ACCV (Spain) | `http://tss.accv.es:8318/tsa` | Provider advertises qualified timestamps; independently verify the issued token/service against EU Trusted Lists | Free for **personal use** by citizens; professional use requires payment; detected uncontracted professional usage is cut off | **PERSONAL ONLY**: require explicit confirmation; no automatic CI use and no background retry |
| APED (Greece) | `https://timestamp.aped.gov.gr/qtss` | APED CP/CPS describes qualified time-stamps and TSA policies | Official JSignPDF instructions show SHA-256 without authentication; CP/CPS identifies prohibited usages including certain testing documents | **NO SYNTHETIC PROBE**: actual document only after individual terms review |
| Sectigo eIDAS | `http://timestamp.sectigo.com/qualified` | Provider documents an eIDAS compliant qualified TSA; token must be independently verified | No official unconditional free-use entitlement established | **RESEARCH ONLY**: do not assume free use; not selected as default |
| B-Trust (Bulgaria) | Provider-specific, subject to contractual provisioning | Qualified service must be independently checked | API/credentials remain external provisioning dependency | No blocking dependency; no guessed credentials |

Official evidence:
- Open TSA: https://open-tsa.eu/ (explicitly *not* eIDAS qualified, free public developer service)
- Open TSA source: https://git.open-tsa.eu/open-tsa/server/src/branch/main/README.md
- ACCV terms and endpoint: https://www.accv.es/en/servicios/administracion-publica/sellado-de-tiempo/
- ACCV TSA policy: https://www.accv.es/vl/fileadmin/Archivos/Politicas_pdf/PoliticaSelladoTiempov2.0.1-ES-2021_pub.pdf
- APED current endpoint: https://aped.gov.gr/allagi-archis-chronosimansis-chronosfragidas-tis-aped/
- APED official JSignPDF instructions: https://aped.gov.gr/wp-content/uploads/sign_with_jsign_apr2022.pdf (p. 7)
- APED CP/CPS: https://pki.aped.gov.gr/repository/downloads/CP-CPS_APED_en_v1.1.pdf (pp. 59–61)
- Sectigo RFC3161 and eIDAS URLs: https://www.sectigo.com/resource-library/time-stamping-server
- EU Trusted Lists: https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls
- Protocol: https://www.rfc-editor.org/rfc/rfc3161

**Provider statements are not independent proof of the trust status of a particular
token at its generation time.** Qualification requires EU Trusted List verification.

## Repeatable live protocol test

On Windows with PowerShell 7:

```powershell
& .\tools\rfc3161_provider_probe.ps1 -Provider open-tsa
```

By default the probe sends a synthetic SHA-256 message imprint only, with a
fresh cryptographically random nonce. For a caller-generated RFC 3161 DER request
(for example from `TimestampQuery::encode`), use the following external-file
round trip; neither request nor reply includes the original PDF:

```powershell
& .\tools\rfc3161_provider_probe.ps1 -Provider open-tsa `
  -RequestPath .\tmp\prepared.tsq -ResponsePath .\tmp\received.tsr
```

The external request is rejected unless it is canonical DER with SHA-256,
32-byte imprint, positive nonce and `certReq=true`; any optional requested
policy must match the returned token. The output is created exclusively only
after the response's cryptographic checks pass. It still does not prove that
the request was built over the correct PDF signature value.

Both modes fail closed on: HTTP status, unexpected MIME, oversize content, malformed DER, rejected
PKIStatus, missing/invalid CMS signer, invalid CMS signature, unexpected TSTInfo,
wrong hash, absent/changed nonce, absent timeStamping EKU or duplicate nonce.
It does **not** validate the TSA certificate chain/revocation, EU LOTL/national
Trusted List, EU DSS, signed PDF document or PAdES profile.

An explicit personal-use-only ACCV test, **not for CI, institutional or commercial use**:

```powershell
& .\tools\rfc3161_provider_probe.ps1 -Provider accv-personal -ConfirmPersonalUse
```

ACCV communicates over plain HTTP. This sends *only* a digest and nonce,
never original files, credentials or PIN. A successfully signed token still
requires independent validation; HTTP interception/denial remains possible.
No automatic failover between providers (especially not qualified to
non-qualified). No rate-limit bypass or bulk processing.

A successful live probe **is not** proof of qualified PAdES-B-T.

## Live result (Open TSA)

On 2026-10-19 a one-shot Open TSA request via RA Core Windows produced:
HTTP 200; Content-Type `application/timestamp-reply`; PKIStatus `granted=0`;
CMS signature PASS; SHA-256 message imprint PASS; random nonce PASS;
timeStamping EKU PASS. TimeStampResp length: 2513 bytes.
TSA signer certificate SHA-256:
`CDA5253F30385CE0F7067D2FB51A1726C3DB5F73A02A0EEDE24CE868CD9497D4`.
Token policy OID: `1.3.6.1.4.1.59085.1.1`.

A separate externally generated TimeStampReq `.tsq` was sent and its
cryptographically verified TimeStampResp `.tsr` was saved with `CreateNew`.
The transport output SHA-256 matched a fresh hash of the stored response:
`EXTERNAL_TSQ_INTEGRATION_PASS`, 2512 bytes. Ephemeral request/response files
were removed after verification.

Not checked: chain/trust-list qualification, revocation, PAdES-B-T, B-LT, B-LTA.

## System integration contract

The Rust `crates/sign/src/timestamp.rs` retains its transport-neutral
`TimestampAuthority` trait. Provider-specific URL, usage permissions and
network transport belong **outside** the cryptographic signing crate.

1. Build the SHA-256 digest over the actual CMS signature value or PDF byte
   ranges according to the selected PAdES level.
2. Construct RFC 3161 request with a fresh unpredictable nonce.
3. Send *only* TimeStampReq DER after explicit provider selection and consent.
4. Require bounded HTTP response and no redirects, then parse
   `timestamp::parse_response` to check signature, nonce and imprint.
5. Check TSA purpose, trust path, time, revocation and EU Trusted List qualification
   separately (do not infer status from provider name, policy OID or URL).
6. Construct PAdES and independently verify the *final* PDF using EU DSS.
7. Never silently downgrade from qualified to non-qualified TSA; never call
   the production TSA automatically in CI.

The source's `tools/btrust_rfc3161_transport.py` remains the separate
B-Trust-specific transport adapter and is not removed or mutated.

Release gates: `TSA_PROTOCOL_TEST=PASS` is possible now;
`TSA_QUALIFIED_EIDAS`, `PADES_B_T`, `PADES_B_LT`, `PADES_B_LTA`
stay **NOT_CHECKED/NO_GO** until proven by independent validation.
