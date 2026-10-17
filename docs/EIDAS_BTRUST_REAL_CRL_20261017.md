# B-Trust Operational Qualified CA — real CRL verification

Read-only evaluation of a downloaded CRL against the signer certificate from the local B-Trust signed-PDF test fixture. No private keys or personal identity data are included.

- CRL URL: `http://crl.b-trust.org/repository/B-TrustOperationalQCA.crl`
- HTTP response: `200`
- Downloaded size: `1777305` bytes
- CRL SHA-256: `ba33ba841b1601da950708965a6ebb98c4d565919db1e11c6e500f373decef3a`
- CRL thisUpdate: `2026-10-17T19:37:04Z`
- CRL nextUpdate: `2026-11-16T19:37:04Z`
- Evaluation time (caller-supplied, **not trusted signing time**): `2026-10-17T20:00:00Z`
- Issuer DN matches embedded B-Trust Operational Qualified CA: `true`
- CRL signature verified against embedded CA public key: `true`
- Leaf serial listed as revoked at evaluation time: `false`
- Prototype output: `GoodAtEvaluationTime`
- Authenticated issuer path: `false`; trusted evaluation time: `false`
- eIDAS qualification: `Indeterminate`

CRL bytes remain in local evidence storage and are not committed. A current CRL does not establish historical non-revocation at an earlier signature time. Further work: issuer path, CRL scope and critical extensions, AKI/SKI, OCSP, trusted timestamp, and Rust production integration.
