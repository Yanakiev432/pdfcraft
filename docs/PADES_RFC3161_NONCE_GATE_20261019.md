# RFC 3161 online TSA request binding — security checkpoint

Date: 2026-10-19
Branch: feature/pades-timestamp-nonce-20261019
Base: PdfCraft 0.9 integration branch (not a production release)

## Implementation
- New `TimestampQuery::with_random_nonce`: obtains an unpredictable positive 63-bit request nonce through the platform CSPRNG (`getrandom::fill`). If entropy is unavailable, signing fails.
- Both `pdf::sign_with_timestamp` (signature-level B-T) and `pdf::timestamp_document` (document timestamp for prospective B-LTA) invoke it before sending a timestamp request.
- The RFC 3161 response parser reads the signed `TSTInfo` nonce and compares it with the original request; missing, changed or duplicated nonces are rejected whenever the request included one.
- When an explicit policy OID was requested, a response asserting another policy is rejected.
- The existing signed CMS hash/imprint verification and size bounds remain in force.

## Verified
- `cargo test --locked --offline -p pdfcraft-sign`: PASS, including 53/53 PDF signature tests, 3/3 CNG test helpers and new negative tests for nonce and policy substitution.
- `cargo clippy --locked --offline -p pdfcraft-sign --all-targets -- -D warnings`: PASS.
- `cargo fmt --all -- --check` and `git diff --check`: PASS.
- Windows cross-target check: run before finalizing this gate.

## Not proof of trusted timestamping
Binding the timestamp reply to the request is *necessary but not sufficient* to authenticate a TSA. No qualified TSA endpoint, credential/account, authenticated QTSP/TSA path, token EKU, revocation evidence, historical EUTSL state or long-term archival renewal was accepted by these tests. PAdES B-T/LT/LTA production issuance remains **NO-GO** until independently verified documents exist.
