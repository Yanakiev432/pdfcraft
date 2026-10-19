# RFC 3161 Open TSA independent PAdES-B-T test-file verification — 2026-10-19

Scope: disposable test fixture only; not an eIDAS qualification declaration.

## Provenance

- GitHub Actions run: https://github.com/Yanakiev432/pdfcraft/actions/runs/39309496517
- Artifact ID: `12215317473`, named `pdfcraft-rfc3161-open-tsa-NONQUALIFIED-TEST`.
- Source commit: `a21aaeb4f7349649ac09040fd8cd74a5b7b64318`.
- Document: `rfc3161-open-tsa-NONQUALIFIED-TEST.pdf`.
- Size: **69,544 bytes**.
- PDF SHA-256: `4d5fd20ca9e6f6152da797ada6a46888609408eb1b56c2e33649f86008ea5d75`.

## Independent verification beyond the producing Rust code

The actual artifact ZIP was retrieved and the contained PDF was inspected with
Poppler `pdfsig`, OpenSSL CMS, Python `pypdf` and `asn1crypto`.

| Check | Observed result |
| --- | --- |
| PDF parse | 1 page, PDF 1.7, not encrypted |
| Signature field 1 | `OpenSSL`, detached test PKCS#7, cryptographic validation **valid** |
| Signature field 2 | `Signature1`, `/ETSI.CAdES.detached`, cryptographic validation **valid** |
| Latest `/ByteRange` | `[0, 17747, 68611, 933]`; covers final 69,544 bytes |
| CMS unsigned signature-timestamp attribute | OID `1.2.840.113549.1.9.16.2.14`, exactly one |
| Encapsulated RFC 3161 token | 2,502 bytes |
| TSA CMS verification (`openssl cms -verify -noverify`) | **PASS** (signature only, no certificate trust) |
| SHA-256 of the PDF CMS signature value | `592e5ac75ffc8e511897691459d7216b82322af7b649e75bf370c52d496215cd` |
| RFC 3161 TSTInfo `messageImprint.hashedMessage` | `592e5ac75ffc8e511897691459d7216b82322af7b649e75bf370c52d496215cd` |
| Full hash equality | **PASS** |
| TSTInfo policy | `1.3.6.1.4.1.59085.1.1` |
| TSTInfo `genTime` | `2026-10-19T19:18:53Z` |
| Test signer certificate trust | **UNTRUSTED** (expected; synthetic signer) |
| Qualified timestamp | **NO** (Open TSA is non-qualified) |
| Independent EU DSS qualified PAdES verdict | **NOT_CHECKED** |

`pdfsig` reports **Signature is Valid** for both signatures, with certificate
issuer **isn't Trusted**. Therefore both PDF signature digests pass, but no
qualified-signature or verified trusted-identity result follows.

The structural test PDF inherited a malformed source stream length warning
(`Missing 'endstream' or incorrect stream length`) visible during rendering.
The PDF renderer nevertheless produced one page and signature verification
succeeded. The source fixture is not a production-ready layout acceptance case.

## Release decision

**NONQUALIFIED_PADES_B_T_CRYPTOGRAPHIC_E2E_PASS**.

Not equivalent to: user B-Trust QES, qualified TSA, independent EU DSS
PAdES B-T/LT/LTA, Microsoft trusted installer, or Word/Excel real token
interoperability. Preserve those independent release gates.
