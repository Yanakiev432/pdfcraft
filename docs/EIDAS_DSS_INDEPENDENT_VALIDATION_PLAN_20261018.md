# Independent DSS cross-validation gate

Official EU DSS release as of October 2026: 6.5.1 (European Commission eSignature DSS). TLv6 compatibility is required since 29 April 2026. Source: https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109107/Digital+Signature+Service+-+DSS

Environment discovery: Windows Java 25.0.2 exists; Ubuntu-24.04 WSL has no java or Maven command. **DSS has not been installed or executed in this run**. Do not claim an independent DSS result.

Required acceptance: run a locally installed and version-pinned DSS 6.5.1 validator with current EU LOTL/TLv6, preserve original PDF bytes, save DSS diagnostic/detailed/simple reports with hashes, compare qualified certificate / QSCD / indication / sub-indication and time constraints against PdfCraft synthesis. Fail closed on untrusted TL signatures, no qualified-signature verdict from this repo alone.

Current observed facts from actual B-Trust PDF: detached CMS ByteRange signature cryptographically valid; CMS signer certificate matches the leaf supplied to PdfCraft; leaf issuer identity matches an authenticated BG CA/QC TSL service. SigningTime and RFC3161 timestamp attributes absent. No trusted signing instant, independent QSCD or full DSS QES decision yet. Do not backdate timestamp or claim QES PASS.

For future signatures, implement provider-mediated qualified signing with a verified TSA, LT revocation material and LTA renewal. Do not operate real hardware token, read PIN or alter OS signing security settings without explicit authorization.
