# Root-link verifier: explicit trust boundary

`tools/eidas_root_link_verify.py` accepts a leaf+issuer PEM bundle, a single root PEM, a SHA-256 pin and a timezone-aware evaluation instant. It verifies the intermediate certificate's signature using the supplied root, issuer/subject equality, AKI/SKI, CA basic constraints and keyCertSign, certificate validity and the root DER digest. It also requires the existing leaf-to-issuer link to pass.

A caller-supplied root and matching caller-supplied pin are **not** an independently authenticated eIDAS trust anchor. The result deliberately sets `independent_root_pin_provenance_verified: false`, `full_certificate_path_verified: false`, and `qualification: Indeterminate` even when the three-certificate link is locally valid. Full PKIX path constraints, independent anchor provenance, historical qualified service status, trusted signing time and QSCD remain separate requirements.

Synthetic tests verify positive and negative cryptographic cases. No root certificate or root pin is asserted as authentic in this repository.
