# B-Trust signed PDF — signing time evidence boundary

The signed PDF signature dictionary contains `/M (D:20261017110754Z)`, i.e. a PDF-declared date of `2026-10-17T11:07:54Z`. This is **not** an independently trusted timestamp.

The extracted CMS signed attributes contain `contentType`, `messageDigest`, and `id-smime-aa-signingCertificateV2` only. `signingTime` is absent. CMS `unsignedAttrs` is absent, hence no embedded RFC 3161 signature timestamp token in this CMS.

The downloaded CRL has `thisUpdate=2026-10-17T19:37:04Z`; the fetched OCSP response has `thisUpdate=2026-10-17T20:42:54Z`. Both are **later** than the PDF-declared signing date. Their `good`/not-listed observations do not, by themselves, authenticate signing time or prove historical certificate status at `11:07:54Z`.

The original PDF and CMS remain read-only. Qualification remains `Indeterminate` pending trusted time and historical policy/chain validation.
