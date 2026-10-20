# EU DSS 6.5.1 local-only validation deployment

## Source and privacy

The official European Commission 6.5.1 release links to `https://ec.europa.eu/digital-building-blocks/artifact/repository/esignaturedss/eu/europa/ec/joinup/sd-dss/dss-demo-bundle/6.5.1/dss-demo-bundle-6.5.1.zip`. HTTP HEAD returned 200, `Content-Length: 617073474` bytes. The Windows host has Oracle Java 25.0.2. Download target **outside Git**: `C:\Users\User\Documents\PdfCraft-DSS-local\dss-demo-bundle-6.5.1.zip`. The bundle includes a runtime; do not assume the system JDK is used.

The official public demo and Javadoc are reachable, but **never upload the signed B-Trust PDF to a remote service**: its signer certificate contains personal information. Run the locally downloaded bundle only on loopback and avoid enabling external network access to the web server.

## Acceptance checklist

1. Finish the download, verify exact byte length 617073474 and record SHA-256. Inspect archive content and launcher before execution. Treat downloaded code as untrusted until provenance is checked.
2. Launch on `127.0.0.1` only, with a separate writable data directory outside the Git repository. Restrict access using Windows Firewall as needed; do not change existing system security policies.
3. Configure a trusted EU LOTL and BG TLv6 feed and independent qualification policy; do not treat a self-supplied root pin as independent authentication.
4. Validate the original signed PDF locally, save DSS diagnostic, detailed and simple reports outside Git, and hash the outputs. Check the signature indication/sub-indication, qualification result, certificate and QSCD at the correct validation instant.
5. Compare against PdfCraft: CMS ByteRange integrity true, CMS signer-to-leaf identity true, leaf-to-issuer cryptographic link true, issuer-to-authenticated BG TSL CA/QC identity true, no embedded CMS signing-time or RFC3161 token. Never promote to QES PASS solely from these facts.
6. Future PAdES: obtain a provider-authorized qualified signature, timestamp at signing, fetch revocation material for LT, then archive timestamps for LTA. Do not sign with hardware token or access PIN without explicit user authorization.

As of this document creation the download was initiated but **DSS execution and independent validation are not yet verified**.
