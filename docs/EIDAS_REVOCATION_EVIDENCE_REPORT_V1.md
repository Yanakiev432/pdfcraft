# Revocation evidence report v1

`tools/eidas_revocation_report.py` combines the existing offline CRL and OCSP checks, binds the input certificate bundle and evidence files by SHA-256, and emits a structured JSON report. It makes no network calls.

`ConcordantGoodAtEvaluationTime` means two mechanisms reported good at a caller-supplied evaluation time; it is **not** a trusted signing-time assertion, historical validity proof, or QES qualification.

The `rust_revocation_provenance` object mirrors the five Rust admission fields. The issuer chain and trusted evaluation time remain false in this version, so `rust_admissible_revocation` is always `Unavailable` and qualification remains `Indeterminate`. The report is not yet wired into the Rust runtime or UI.

Never commit real signer certificates or OCSP/CRL evidence containing personal data. The report hashes the inputs but does not print signer names or certificate serials.
