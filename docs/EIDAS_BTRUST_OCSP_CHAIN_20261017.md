# B-Trust OCSP responder cryptographic acceptance — 2026-10-17

The embedded OCSP responder certificate is issued by the B-Trust Operational Qualified CA certificate present in the signed PDF CMS. It declares EKU `id-kp-OCSPSigning` (`1.3.6.1.5.5.7.3.9`), with validity from 2022-04-21 to 2027-04-21.

OpenSSL invocation (local WSL evidence directory):

```sh
openssl ocsp -respin ~/pdfcraft-eidas-evidence/btrust-ocsp-response.der -issuer ~/pdfcraft-eidas-evidence/btrust-issuer.pem -cert ~/pdfcraft-eidas-evidence/btrust-leaf.pem -partial_chain -CAfile ~/pdfcraft-eidas-evidence/btrust-issuer.pem -no_nonce
```

Result: `Response verify OK`; leaf certificate status `good`; `thisUpdate` 2026-10-17T20:42:54Z and `nextUpdate` 2026-11-16T19:37:04Z.

**Trust boundary:** `-partial_chain` explicitly treats the locally supplied intermediate CA as a trust anchor. This verifies the OCSP responder chain and signature relative to that CA; it does **not** independently authenticate the CA against a root or full historical eIDAS policy. No `-noverify` was used for the accepted result. Trusted signing time, nonces/replay policy and complete qualification remain unresolved. Verdict `Indeterminate`.
