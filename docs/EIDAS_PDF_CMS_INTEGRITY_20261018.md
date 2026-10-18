# Detached CMS integrity verification

`tools/eidas_pdf_cms_integrity.py` verifies the cryptographic detached CMS signature over the exact two PDF ByteRange segments using OpenSSL `cms -verify -binary -noverify`. It requires one ByteRange, exact end-of-file coverage, a hex Contents gap, bounded PDF/CMS input and no appended bytes.

Real B-Trust PDF SHA-256: `3016d0e0cbd7f72fa7dbc4c29685f714176d978f2c300f022c3d617d7abc9c9a`. Signed ByteRange SHA-256: `dea0e09cd8e95ca368b15848557b5f230012c65ad50ee83d05607f20e08867f7`. The real cryptographic verification returned `cms_detached_signature_integrity_verified: true`.

Integrated synthesis supports optional `--verify-pdf-cms` and returns `pdf_cms_integrity` evidence. This validates CMS integrity using embedded signer material but deliberately skips PKIX trust (`-noverify`); it does not by itself bind CMS signer identity to a specific independently validated leaf, or establish trusted signing time, QSCD or QES. Full validation remains Indeterminate.
