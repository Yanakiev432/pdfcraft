# Authenticated BG TSL CA/QC issuer binding

The B-Trust synthesis now reports `issuer_ca_qc_identity_bound_to_authenticated_tsl` only when the leaf-to-issuer cryptographic link is verified AND the exact issuer DER SHA-256 matches an effective CA/QC service identity from the BG TSL authenticated through EU LOTL. The TSL file is SHA-256 checked before and after the CA/QC extraction.

Real B-Trust result at the caller-supplied 2026-10-18T14:30:00Z: `issuer_ca_qc_identity_bound_to_authenticated_tsl: true`. This provides an authenticated CA/QC service identity and does not depend on asserting the independently downloaded root certificate is trusted.

Important limits: a service identity match at an evaluation instant is not historical status at an authenticated signing instant; leaf certificate qualification, QSCD, trusted time, independent rollback protection, and all PKIX critical extension processing are not yet established. `full_certificate_path_verified` and `qes_pass` remain false. The result is `Indeterminate`.
