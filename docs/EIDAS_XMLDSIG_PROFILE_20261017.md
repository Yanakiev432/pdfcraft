# Observed EU/BG XMLDSig profile — 2026-10-17

Observed in downloaded XML snapshots (not verified): both EU LOTL and BG TSL contain one XMLDSig Signature with rsa-sha512, two references: empty URI for the enveloped document (enveloped-signature and exclusive XML canonicalization transforms), and a same-document #xades-id reference (exclusive canonicalization). This is a profile observation, not proof of XMLDSig validity.

Environment: xmlsec1 is absent in WSL Ubuntu-24.04; Python lxml is also absent. No system package was installed. Full cryptographic verification must enforce reference resolution, ID uniqueness, anti-wrapping protections, canonicalization, SignedProperties integrity, verified signer certificate and trusted signer history. No signer identity, LOTL pointer or service status may be trusted based on these observations alone.

Inputs: EU https://ec.europa.eu/tools/lotl/eu-lotl.xml ; BG https://crc.bg/files/_en/TSL_BG.xml . Both remain UNVERIFIED and qualification remains Indeterminate.
