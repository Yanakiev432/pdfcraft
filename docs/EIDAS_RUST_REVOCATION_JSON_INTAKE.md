# Rust intake of offline revocation report v1

`qualification::from_offline_revocation_report` parses `pdfcraft.eidas.revocation-evidence.v1` JSON with a 256 KiB input limit and strict top-level/provenance fields. It rejects forged trusted-time or issuer-chain claims and incompatible qualification fields.

The report remains **advisory**. Rust does not use a JSON flag as proof of an authenticated issuer chain or trusted signing time, and therefore does not promote revocation evidence to Confirmed or claim QES.

This is a library integration boundary only. A future independent trust/time verifier and UI integration are required. The Rust dependency lockfile was updated offline.
