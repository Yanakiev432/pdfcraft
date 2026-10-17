# Revocation evidence admission contract

`qualification::with_verified_revocation` accepts a revocation finding only when all fields of `RevocationProvenance` are verified by an independent verifier: issuer chain, evidence signature, certificate identity, scope/freshness, and trusted evaluation time.

This structure is an admission boundary, not an OCSP/CRL parser or proof of historical revocation status. A caller must not set provenance flags merely because a response says GOOD or a certificate is absent from a CRL.

Current B-Trust CRL and OCSP investigations have not established a trusted signing/evaluation time and independently anchored issuer chain. Therefore they must not set all flags to true; eIDAS qualification remains Indeterminate.

Missing provenance cannot replace an already rejected revocation finding with a positive result.
