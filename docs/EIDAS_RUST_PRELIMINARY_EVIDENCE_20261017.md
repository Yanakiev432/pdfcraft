# Rust preliminary qualification evidence: fail-closed changes

The PdfCraft Rust qualification adapter now does not infer independently trusted signing time merely from a parsed `timestamp_time`. Nor does it promote an embedded PDF revocation-status message into verified revocation evidence. Both remain `Unavailable` until an authenticated evidence verifier supplies them.

The separate explicit `Rejected` branch for a reported revoked certificate remains intact. This adapter is preliminary and must not present `Qualified` from PDF metadata alone.

Follow-up work: typed OCSP/CRL provenance with independent trust chain, timestamp token and TSA chain verification, service qualification history and QSCD at the proven signing time, and end-user UI integration.
