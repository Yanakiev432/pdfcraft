# EU DSS 6.5.1 / TLv6 — independent PAdES profile boundary

Date: **2026-10-21**. The European Commission's [DSS portal](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109107/Digital%2BSignature%2BService%2B-%2BDSS) identifies **DSS 6.5.1** as the October 2026 release and warns that **Trusted List v6 (TLv6)**, in ETSI TS 119 612 v2.4.1, applies from **29 April 2026**. Earlier DSS builds or trust-list caches may no longer reliably validate qualified services. A version string alone is *not* independent evidence of an authentic EU LOTL / national Trusted List.

## Proven local baseline (not a timestamped signature)

The locally stored real B-Trust evaluation from 2026-10-18 used DSS 6.5.1 on Windows loopback and returned:

- Exactly one signature, one valid signature.
- `Indication: TOTAL_PASSED`.
- `SignatureLevel.value: QESig`.
- `SignatureFormat: PAdES-BASELINE-B`.
- `Timestamps: null`.

The report and signed personal PDF remain only on the Lenovo. The baseline establishes an **independently observed QES on a B-level PDF at validation time**; it does *not* establish a qualified signature timestamp at signing time, PAdES-B-T, B-LT or B-LTA. No USB signing or PIN operation is performed by these checks.

## Opt-in validation command

The existing `tools/eidas_dss_local_verify.py` already enforces a loopback-only HTTP endpoint with redirects and proxies disabled. The new `tools/eidas_dss_profile_boundary.py` invokes that same adapter, receives its returned **raw report and summary in one call**, verifies the raw response digest, and re-hashes the original signed PDF after the response to reject stale/replaced evidence.

With the official, independently inspected local DSS 6.5.1 instance running on `127.0.0.1:8080` and a disposable or expressly authorized signed PDF:

```powershell
python -I .\tools\eidas_dss_profile_boundary.py 'C:\path\to\authorized-signed.pdf'
```

**Do not send personal B-Trust PDFs to the Commission's public demonstration application, CI, GitHub, unapproved TLS endpoints or to another person's computer.** This command sends the bytes only to the explicitly chosen localhost validator; the validator may separately fetch trust lists and revocation data over approved public endpoints.

The resulting *PII-free* JSON distinguishes:

- `independent_dss_qes_at_observed_validation`: whether the same local DSS adapter independently observed one QES `TOTAL_PASSED`.
- `dss_observed_profile` and `dss_profile_structural_level`: format and validated timestamp **structure** observed by DSS.
- `dss_timestamp_records`: number of DSS timestamp nodes with `Indication=TOTAL_PASSED`.
- `qualified_rfc3161_qtsa_at_generation_time: NOT_CHECKED`.
- `eu_lotl_national_tlv6_authenticity: NOT_CHECKED_BY_THIS_CLASSIFIER`.
- `dss_runtime_version_and_trust_policy: NOT_ATTESTED_BY_THIS_CLASSIFIER`.
- `qualified_pades_b_t_b_lt_b_lta_acceptance: NO_GO`.

**Neither a `PAdES-BASELINE-LTA` format label nor a successful embedded RFC 3161 cryptographic signature alone demonstrates an eIDAS-qualified time-stamp service.** That requires independently authenticated and time-appropriate EU LOTL/national Trusted Lists, a trusted TSA certificate/service match at token generation time, revocation and real final-document EU DSS acceptance.

This conservative classifier deliberately does not award a qualified B-T/LT/LTA release PASS. That separate qualification bridge must be implemented and accepted independently; do not weaken this rule to get a green CI badge.

## Negative verification

`python -B tools/test_eidas_dss_profile_boundary.py` uses synthetic, redacted JSON. Its cases cover a real-B-Trust-style B-level QES, fictitious timestamped T/LT/LTA results that remain **NO_GO**, missing timestamps, failed timestamps, mismatched raw hash, contradictory adapter findings, multiple signatures, a top-level timestamp masquerading as a signature, unsupported profiles, private certificate-subject leakage and noninteger signature counts.

These offline tests never contact a real provider, a token, a trust list or DSS. Their PASS demonstrates **parser safety and classification logic only**.

## Separate qualified release conditions

1. QTSA terms and provider authorization, including the correct use category.
2. Independent EU DSS + authentic TLv6-capable EU/national Trusted Lists and verified historical qualified service status at the exact `genTime`.
3. Real final PAdES-B-T PDF signature timestamp over the exact CMS signature value and nonce; B-LT additionally requires complete appropriately valid revocation/certificate evidence; B-LTA requires appropriate archival document timestamps and a renewal policy.
4. Physical B-Trust USB PIN prompt through the legitimate provider UI, when actually authorized for the signing operation.
5. Independently signed Windows release artifacts from an approved code-signing publisher and Windows SAC validation, **not** the user's document-QES credential.

The software work is not blocked by BORICA support case SD1614999; legally qualified delivery is independent and still **NO_GO**.
