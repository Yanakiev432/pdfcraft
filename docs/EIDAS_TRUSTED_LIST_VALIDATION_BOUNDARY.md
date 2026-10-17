# eIDAS trusted-list validation boundary

Status: architecture and conservative evidence gates implemented; EU trusted-list cryptographic verification **not implemented**.

The `pdfcraft-sign::qualification` module must not claim that a B-Trust certificate, a trusted Windows root, a successful CMS signature, or a QCStatements extension proves qualified electronic signature status. An external verifier must authenticate the EU LOTL and the member-state list (including signing certificates and rollover), follow the authenticated national-list pointer, match the provider/service and service history at the relevant validation time, and interpret qualified-certificate and QSCD qualifiers. It must also account for revocation and trusted signing time.

`TrustedListProvenance` currently carries flags supplied by a caller; these flags are **not cryptographic proof** and MUST NOT be populated from arbitrary documents, user input, issuer names or unsigned HTTP/XML. `with_verified_trusted_list` is only an evidence-composition boundary, not an XML signature verifier. Do not expose `Qualified` as an eIDAS verdict in a UI until a real trusted verifier controls this boundary.

The test fixture where all fields are `Confirmed` tests aggregation logic only; it does not validate any real trusted list. In the absence of a verifier, use `TrustedListFinding::unavailable()` and report `Indeterminate`.

Next implementation milestone: verify LOTL/national TL XML signatures using independently pinned trust anchors, enforce safe XML parsing, validate signed pointers and service history, and bind the evidence to the signer certificate, trusted validation time and audit trail. Follow with live EU/BG trusted-list acceptance tests and revocation validation. No PDF or private key mutation is needed.
