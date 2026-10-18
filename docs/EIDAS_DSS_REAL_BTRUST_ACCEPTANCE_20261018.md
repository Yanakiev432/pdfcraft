# Independent EU DSS 6.5.1 real B-Trust acceptance — 2026-10-18

## Provenance

Local official European Commission DSS 6.5.1 demo bundle, 617073474 bytes, downloaded from the Commission artifact repository. Local archive SHA-256: `f0e10bb218795b966824887a8c73b555ab9d88a8e84997882d3e5a807cc9cb37` (no independently published upstream digest comparison). Unpacked outside Git to `C:\Users\User\Documents\PdfCraft-DSS-local\unpacked\dss-demo-bundle-6.5.1`. Tomcat 11.0.27 binds HTTP to 127.0.0.1:8080. The supplied runtime reports Java 26.0.2.1. The webapp uses online trust-list and revocation retrieval.

The original real B-Trust PDF was posted ONLY to `http://127.0.0.1:8080/services/rest/validation/validateSignature` from the same Windows host, never to the public demo. Original PDF SHA-256: `3016d0e0cbd7f72fa7dbc4c29685f714176d978f2c300f022c3d617d7abc9c9a`.

Raw local-only DSS response: `C:\Users\User\Documents\PdfCraft-DSS-local\evidence\dss-validation-20261018.json`, 157082 bytes, SHA-256 `1d65bb1eb4afbd8d285a16b5ba49e929a0d1daa654f176f2e210c72ca7e338bc`. It contains personal certificate details; do not commit or publish it.

## Independently observed simple report

- Policy: `QES AES/QC AES TL based`.
- `SignaturesCount: 1`, `ValidSignaturesCount: 1`.
- `Indication: TOTAL_PASSED`.
- `SignatureLevel.value: QESig` (Qualified Electronic Signature).
- `SignatureFormat: PAdES-BASELINE-B`.
- `SigningTime: 2026-10-17T11:07:54Z` (PDF-declared; NOT an independently trusted timestamp).
- `BestSignatureTime: 2026-10-18T20:22:27Z` (validation time; NOT evidence of an October 17 trusted signing time).
- `ValidationTime: 2026-10-18T20:22:27Z`.
- `ExtensionPeriodMax: 2027-01-15T00:00:00Z`.
- `Timestamps: null` (no embedded signature timestamp token).

**Conclusion:** independent DSS validation of this exact B-Trust PDF returns a qualified electronic signature with TOTAL_PASSED at the observed validation time. This is a DSS-observed QES PASS for this test document, NOT proof of trusted October 17 signing instant, NOT an LTA guarantee, and NOT authorization to automatically mark arbitrary PDFs as QES. Our conservative PdfCraft synthesis still returns `qes_pass: false` because it does not yet implement DSS qualification logic; keep the two verdicts separate.

Next: add a strictly opt-in DSS local-only integration, import the actual report with input hash matching and schema checks, and distinguish `independent_dss_qes_pass` from `native_qes_pass`. Add negative tests before exposing a combined product verdict.
