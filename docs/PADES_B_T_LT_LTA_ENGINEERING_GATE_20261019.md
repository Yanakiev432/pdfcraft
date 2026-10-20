# PAdES B-T / B-LT / B-LTA acceptance, issue and limits

Date: 2026-10-19
Project: PdfCraft signatures fork, branch feature/universal-signature-providers

## Verified source capabilities (do not confuse with qualification)

- `crates/sign/src/pdf.rs`: `sign_with_timestamp` applies an RFC 3161 CMS-signature timestamp at signing time (B-T serialization); `timestamp_document` adds an incremental document timestamp.
- `crates/sign/src/dss.rs`: `embed` writes incremental /DSS and /VRI certificate, CRL and OCSP blobs, but explicitly accepts **caller-supplied, not independently authenticated** evidence. A file with these dictionaries is **not by itself** a verified B-LT PDF.
- Existing Rust tests use deterministic locally generated TSA identities. Their passing proves format handling only, not a trusted public/QTSP timestamp or eIDAS archival qualification.
- Existing B-Trust signed PDF was independently classified by local EU DSS 6.5.1 as `QESig` / `TOTAL_PASSED` / `PAdES-BASELINE-B`, with SHA-256 `3016d0e0cbd7f72fa7dbc4c29685f714176d978f2c300f022c3d617d7abc9c9a`. This does not independently prove trusted signing time.

## New fail-closed independent profile gate

Use `tools/eidas_pades_profile_gate.py`. It sends the existing PDF only to a loopback EU DSS endpoint through `tools/eidas_dss_local_verify.py`, reads actual DSS classification and checks that the PDF was unchanged after validation (SHA-256). It rejects unknown formats, non-QES/indeterminate verdicts, and versions below the requested minimum.

Example:

```powershell
& 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe' -I tools\eidas_pades_profile_gate.py 'C:\Users\User\AppData\Local\Temp\pdfcraft-btrust-real-sign-20261017.pdf' --minimum LT
```

Current sample: `--minimum B` returns 0/PASS; `--minimum T`, `LT` and `LTA` return 1/NO-GO as required. Four negative/positive unit tests pass without network or hardware keys.

**Scope limit:** Current EU DSS adapter requires exactly one recognized actual signature; it is not yet a multi-signature or full lifetime-renewal validator. Its single `SignatureFormat` classification is not a separate validation of the quality of the TSA, trust list snapshots or evidence renewals. The gate explicitly reports these unproven dimensions as false.

## Issuance acceptance stages

1. **B-T**: Explicit opt-in RFC 3161 TSA endpoint and trust policy; the response must match the hash of the signature value, be verified cryptographically, be within algorithm/nonce/size bounds, and have an independently verified chain and timestamp authorization at its generation time. Do not use the signer workstation clock as evidence. A qualified timestamp requires separate QTSP/TSL proof.
2. **B-LT**: Obtain exact signer, intermediate and TSA certificates plus signed OCSP/CRL evidence corresponding to the validation interval; independently verify issuer/signature, certificate and responder constraints, freshness, serial/status, and historical trust service status **before** embedding to /DSS and /VRI. No fabricated or synthetic revocation blobs for production. Preserve the original signed revisions.
3. **B-LTA**: After accepted LT evidence, append an authenticated RFC 3161 **document** timestamp covering the whole resulting document revision; independently validate its digest, signer/chain, trusted time, and maintenance/renewal policy. A single document timestamp does not guarantee long-term archive viability without periodic renewals.
4. For each stage, send the entire resulting PDF to independently configured EU DSS; require the exact explicit `SignatureFormat` minimum, qualified status, `TOTAL_PASSED`, PDF SHA-256 binding, and a separate evidence-level review. Archive the response, validation policy identifier, TSL snapshot/provenance and hashes without uploading personal signed documents to public source control.

## External blockers (not workarounds)

- No explicitly configured authorized TSA issuance endpoint/account or proven qualified timestamp service contract for new real signatures. It would be dishonest to claim trusted B-T on the existing baseline-B file.
- No fully validated and timestamp-aligned signer/TSA revocation evidence bundle sufficient for B-LT on the real PDF.
- No trusted document-timestamp + archival renewal evidence sufficient for B-LTA.
- Do not use the B-Trust PIN, smart-card signing operation or any unapproved signature retries to fake proof of progress.

**Production issue verdict: B-B validated; B-T/B-LT/B-LTA issuance NO-GO until these concrete inputs and independent outputs exist.**
