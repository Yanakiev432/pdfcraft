# B-Trust certificate link validation — 2026-10-18

The offline `tools/eidas_certificate_path_verify.py` validates the leaf-to-intermediate signature, issuer distinguished name, issuer BasicConstraints CA flag and keyCertSign usage, leaf non-CA flag, AuthorityKeyIdentifier/SubjectKeyIdentifier equality, and both certificate validity windows at a caller-supplied evaluation time. Only a pair of PEM certificates is accepted. The result exposes no personal signer identity.

Real B-Trust PDF embedded certificates: `local_link_verified: true`; issuer DER SHA-256 `499a9ca8b47ee84437f90b96fb40413ea293f9b3942a160837a0c67b0ec5ba0c`, equal to the national TSL CA/QC candidate digest. The validation is included in the combined offline synthesis.

This is NOT a full certificate path validator. It does not authenticate a root or the issuer chain, process all PKIX constraints, establish trusted signing time, validate QSCD, or prove historical revocation status. These flags remain false and the QES qualification is `Indeterminate`. Unit tests cover positive synthetic RSA certificates and negative signature, AKI, CA constraints, and expiry cases.
