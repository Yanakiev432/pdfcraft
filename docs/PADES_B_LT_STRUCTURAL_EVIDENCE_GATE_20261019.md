# PAdES-B-LT structural evidence intake — checkpoint 2026-10-19

Branch: feature/pades-lt-evidence-gate-20261019
Parent: feature/pades-timestamp-nonce-20261019

## Engineering result

A new Rust API, pdfcraft_sign::dss_checked::embed_checked, performs a
fail-closed structural / cryptographic preflight BEFORE writing DSS/VRI.

The input is the original signed PDF bytes, an explicitly nominated
direct issuer X.509 certificate, a time supplied by the caller, and
caller-supplied DER certificates and revocation evidence.

It enforces:

- One approval field signature; exact signed bytes must cryptographically
  verify against the supplied issuer. No document timestamp or preexisting
  DSS/unknown previous evidence merge.
- Signer X.509 extracted from the actual PDF, verified against the issuer,
  issuer CA constraints and validity interval at the nominated time.
- Exact DER for both the PDF signer and issuer must be included. Other
  intermediate/TSA certificates are deferred to a later chain-aware gate.
- Strict count and total-size limits on all supplied evidence, parsed X.509
  DER, and parsed CRL/OCSP structures.
- CRL or OCSP signature verified against the immediate issuer/delegated
  authorized responder, matching signer serial/issuer, and freshness
  coverage at nominated time.
- Every supplied CRL/OCSP must be verifiable and not assert revocation.
  A single good response cannot mask a revoked, malformed, stale or
  unrelated second response. At least one Good status required.
- Only after these checks, append DSS/VRI incrementally. Previously signed
  PDF revisions are preserved.

The existing low-level dss::embed accepts caller-supplied bytes and is
explicitly NOT a qualified-evidence gate. Previously published format-only
tests using "synthetic ocsp" and "synthetic crl" prove serialization only.

## Test fixture and measurement

The file crates/sign/tests/data/lt-ca-test.p12 was generated locally for
the test suite on 2026-10-19 using OpenSSL and the public TEST password
"test". It contains a disposable CA private key generated solely for
automated tests. This is never a production identity, real B-Trust
credential or trust anchor.

The new integration test creates a PDF signed by the disposable CA,
constructs a legitimate test-only CRL and verifies DSS append and the
original signature. It also rejects absent revocation evidence, arbitrary
synthetic bytes, revoked/late/incorrectly signed CRL, malformed OCSP,
certificate substitution, tampering with signed PDF content and blind
extension of an existing DSS.

## What is not yet qualified

This API intentionally DOES NOT:
- establish that the caller-supplied issuer appears as a qualified QTSP in
  official EU/Member State Trusted Lists at the historical signing time;
- independently prove that its caller-supplied time is from qualified
  RFC 3161 timestamp;
- validate full signer/intermediate/root/TSA/responder chain revocation and
  historical policy state;
- map independent evidence for multi-signature documents and repeated
  archival renewals;
- perform independent EU DSS PAdES B-LT or B-LTA validation on a real
  B-Trust signed PDF.

For actual PAdES-B-LT acceptance, these are **mandatory separate gates**.
Production issuance and B-LT qualification remain NO-GO. No token PIN,
private production key, real signed personal document or system security
policy has been used or changed.
