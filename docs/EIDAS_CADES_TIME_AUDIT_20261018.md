# Real B-Trust CMS time evidence audit

`tools/eidas_cades_time_audit.py` performs a bounded, read-only inventory of CMS attribute OIDs using OpenSSL's CMS parser. It does not validate timestamp tokens, signer identity or CMS cryptographic integrity; every reported attribute is explicitly unverified.

For `/home/yanakiev/pdfcraft-eidas-evidence/btrust-signed-cms.der`, signingTime, signatureTimeStampToken, contentTimeStamp and archiveTimeStampV3 are absent. messageDigest and signingCertificateV2 are present.

Consequently the CMS itself does not supply a trusted signing instant. PDF `/M` is not a trusted timestamp. CRL and OCSP observations at a later evaluation instant cannot automatically be promoted to revocation-at-signing-time proof. QSCD requires separate independent evidence. QES stays Indeterminate.

This is an attribute inventory, not a complete CAdES signature validation or ASN.1 semantic audit. Tests include synthetic presence, non-attribute text and size bounds.
