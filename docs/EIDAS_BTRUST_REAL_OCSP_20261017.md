# Real B-Trust OCSP response — 2026-10-17

An OCSP request for the end-entity certificate from the local signed-PDF test was sent to `http://ocsp.b-trust.org`.

- HTTP status: `200`; response size: `2092` bytes
- OCSP response SHA-256: `cef34027d64c1a35b82622e1ee64b919cf2f25dd038373cf2f64fceb8d4b554a`
- Response status: `SUCCESSFUL`
- Unauthenticated claimed certificate status: `GOOD`
- `thisUpdate`: `2026-10-17T20:42:54Z`
- `producedAt`: `2026-10-17T20:42:54Z`
- `nextUpdate`: `2026-11-16T19:37:04Z`
- One responder certificate embedded.
- OpenSSL verification with embedded issuer as `-VAfile` failed with `unable to get local issuer certificate`.
- Therefore: **OCSP response signature/trust NOT yet verified**, no `Good` verdict accepted for QES.

Next: validate OCSP response signature, responder certificate authorization and issuer chain, CertID hash/serial binding, nonce policy and trusted evaluation time. Preserve original DER locally, outside Git.
