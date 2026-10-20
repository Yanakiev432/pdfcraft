# B-Trust offline evidence synthesis — 2026-10-18

Run `tools/eidas_btrust_synthesis.py` with the real signed PDF, locally archived EU LOTL and BG TSL, embedded certificate PEM, issuer CRL, OCSP response DER, and an explicit ISO-8601 evaluation time. This tool invokes the EU OJ-pinned XMLDSig/LOTL-to-BG verifier, exact DER CA/QC TSL matching, and independent CRL/OCSP inspectors in one process. It emits no personal signer identity and does not include raw certificates.

Real evidence check at claimed evaluation time `2026-10-18T14:30:00Z`:

- EU LOTL sequence 397 and BG TSL sequence 64: cryptographic chain authenticated and publication windows valid.
- Exactly one CA/QC service candidate matches the PDF embedded CA certificate DER SHA-256 `499a9ca8b47ee84437f90b96fb40413ea293f9b3942a160837a0c67b0ec5ba0c`.
- CRL/OCSP combined observation: `ConcordantGoodAtEvaluationTime`. This is **not** an authenticated revocation state at historical signing time.
- PDF `/M` is document-declared, not a trusted timestamp; CMS has no `signingTime` or timestamp token. Independent QSCD, full path, trusted signing time, anti-rollback witness, and historical revocation proof remain unverified.
- Final `qualification: Indeterminate`; `qes_pass: false`.

This is a diagnostic, not a QES validator. The matching CA/QC historical status uses the caller-supplied evaluation time and cannot prove when the signer actually signed. A trustworthy QES verdict must not be manufactured by replacing missing evidence with booleans.