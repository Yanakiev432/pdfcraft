# EU/BG trusted-list read-only inventory — 2026-10-17

The inventory script `tools/eidas_lotl_inventory.py` reads an already downloaded XML file with size limits and rejects DTD/entity declarations. It does not fetch URLs, resolve XML references, verify XMLDSig signatures, or authenticate any issuer.

Source: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`
- 483294 bytes; SHA-256 `a36d0053df1afa96c88ede817a585b3168afeba84c1984a0e6cc5642453e70e6`
- 1 XMLDSig Signature element; unverified Bulgarian pointers: `https://crc.bg/files/_en/TSL_BG.pdf`, `https://crc.bg/files/_en/TSL_BG.xml`.

Source: `https://crc.bg/files/_en/TSL_BG.xml` (URL found in the EU XML; authenticity not yet proven)
- 627531 bytes; SHA-256 `b7ac246a31e6d805f4830cb36449ed86cdecef328a66a37b9bca9c2969b6fd66`
- 1 XMLDSig Signature element; **signature not verified**.

Both XML files were downloaded read-only; no PDF or key material was touched. The hashes identify observed snapshots, not trust anchors. Qualified status: **Indeterminate**. Next milestone is real signature verification with authenticated LOTL trust anchors, XML reference wrapping defenses, national-list signer rollover and service-history checks.
