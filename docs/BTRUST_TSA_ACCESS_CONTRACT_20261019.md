# B-Trust RFC 3161 transport — provider access contract

Date: 2026-10-19
Status: **Transport prepared and locally tested. Provider access and issuance NOT accepted.**
Branch: feature/pades-timestamp-nonce-20261019

## Official published endpoints

BORICA Developer Portal: https://www.b-trust.bg/services/developers

- Test Time Stamp API: `http://tsatest.b-trust.org`
- Production Time Stamp API: `https://tsa.b-trust.org` (HTTP variant is also listed, but this adapter deliberately forbids plaintext credentials and uses HTTPS only).

BORICA states that active trust-service access is limited to preauthorized IP addresses or usernames/passwords assigned by BORICA. The developer portal's service-access process requires authorization/registration. No account, approval, IP allowlisting, paid contract, TSA trust path or production quota is established by this repository.

## Prepared transport, not a QES validator

`tools/btrust_rfc3161_transport.py` takes an already constructed RFC 3161 TimeStampReq DER **not the PDF**, sends an HTTPS production (only when explicitly authorized) or test HTTP request with media type `application/timestamp-query`, and accepts only bounded DER `application/timestamp-reply` replies.

Key properties:
- Test mode by default requires explicit `--server test`; production requires **both** `--server production` and `--allow-production`.
- Credentials are optional, exclusively loaded from `PDFCRAFT_TSA_USERNAME` and `PDFCRAFT_TSA_PASSWORD` environment variables and sent only over HTTPS (never the HTTP test endpoint). This assumes BORICA has specifically authorized Basic authentication; confirm the agreed mechanism before real use.
- Request maximum: 1 MiB; response maximum: 4 MiB; configurable timeout bounded 1–60 seconds.
- An error never implies issuance and does not create a successful output; existing files cannot be overwritten.
- No user's PDF, personal document, B-Trust private key or PIN is transferred or logged.
- The adapter does **not** prove the server is a qualified TSA. It neither parses the TSTInfo signature nor validates a QTSA path, cert revocation, EUTSL history or time evidence.

Example **only when a developer test account or IP access has been authorized by BORICA**:

```powershell
& 'C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe' -I tools\btrust_rfc3161_transport.py --server test --request .\fixture-rfc3161-query.der --response .\fixture-rfc3161-reply.der
```

The request must be prepared by Rust `TimestampQuery` and its response parsed with `pdfcraft_sign::timestamp::parse_response`, including the random nonce/policy binding. **Only** a separate authenticated TSA chain/trusted-time and EU DSS validation can accept a real B-T result.

## Acceptance / remaining external dependencies

1. BORICA must provide or approve usable test access, exact endpoint/path, authentication mechanism, and trust-service policy OID; if payment is required, get explicit user cost approval.
2. Test a synthetic hash only; require bounded RFC 3161 DER response and cryptographically validated nonce/imprint/TSA signer with official trust chain.
3. Bind `TimestampAuthority` at a **real application signing boundary** to this transport without transmitting documents; the present Python script is a stand-alone transport primitive, not an integrated signing workflow.
4. Re-sign an explicitly authorized disposable PDF with the B-Trust token/PIN handled by official provider UI, request a qualified timestamp from the approved TSA, and independently validate the resulting file with local EU DSS.
5. For B-LT, collect and independently authenticate OCSP/CRL with appropriate temporal trust evidence; for B-LTA, append and verify a protected document timestamp and define archival renewal policy.

## Local test evidence

`python -I tools/test_btrust_rfc3161_transport.py`: 9/9 PASS, no network calls, including redirect rejection. These tests do not simulate real qualified TSA issuance.
