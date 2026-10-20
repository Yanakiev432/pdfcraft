# B-Trust qualified RFC 3161 — manual nonprofit fallback and release acceptance

Updated 2026-10-20. **NOT a claim of PAdES-B-T/LT/LTA qualification.**

## What is verified

Official B-Trust Qualified Time Stamp information:
https://www.b-trust.bg/services/time-stamp-issue

The page describes an RFC 3161 manual form that accepts a `.tsq` request and
offers qualified timestamp service **for nonprofit purpose**. The provider
separately states that automated integration requires contacting B-Trust.
It does not promise unlimited free automated usage or accept any PAdES
embedding workflow. The form also offers a `.tsr` lookup/validation.

Our engineering service case **SD1614999** was acknowledged by BORICA on
2026-10-19. The acknowledgement is *not* a grant of endpoint access or a
positive provider integration acceptance.

The free Open TSA path in CI is expressly **NONQUALIFIED**, and its successful
cryptographic signatures cannot be relabeled as QTSA.

## Manual nonprofit experiment (no user document upload)

1. Work only with a user-authorized **disposable** test document, never
   a sensitive PDF, private key, certificate PIN, or production signing identity.
2. The `.tsq` MUST be derived from **SHA-256 of the exact CMS signature
   value** of the final candidate PDF `/ETSI.CAdES.detached` signature,
   **not** a SHA-256 of the PDF file or of the original document.
   Produce a fresh positive unpredictable RFC 3161 nonce and request TSA
   signing certificate inclusion (`certReq=true`).
3. Capture and persist a fail-closed pending context: PDF file digest,
   authenticated CMS signature digest, DER `.tsq`, unique nonce,
   exact signature dictionary and reserved `/Contents` window,
   target output identity, timestamps and provenance. **Existing signing
   bridge does not yet expose a supported resumable offline PAdES session.
   Never make up a request from another signer or another PDF.**
4. A human may visit the **official** URL above and upload only the
   eligible `.tsq`, observing the provider's conditions, and retrieve
   `.tsr`. No scripts may scrape this form, impersonate an API or exceed
   the permitted conditions.
5. Validate TimeStampResp DER strictly: accepted status, one token,
   CMS signature valid, SHA-256 messageImprint byte-equal to the pending
   signature hash, nonce byte-equal to the request, asserted policy,
   trusted TSA certificate chain, issuer and revocation proofs, and
   service qualification `QTSA` **at token generation time** from verified
   EU/ national trusted lists (not a self-declared certificate subject).
6. Do **not** embed into PDF unless the exact deterministic pending PDF
   byte ranges and CMS representation can be resumed without invalidating
   the existing document signature. A new PDF with a substituted CMS
   signature or changed signing bytes is **not** the same pending request.
7. Independently validate the **actual final PDF** using local EU DSS with
   trustworthy synchronized EU LOTL/national lists. Qualified baseline
   status requires a positive DSS determination, not only OpenSSL/Poppler
   cryptographic validity. PAdES-B-LT needs adequate revocation and
   certificate validation material; B-LTA further requires verified
   archival document timestamps and renewal lifecycle.
8. The provider's time-stamp web validation option is limited to recent
   status information (official page states two months); preserve evidence
   and validation reports for long-term acceptance and do not assume the
   website itself supplies required PAdES-LT material.

## Release controls

- `BTRUST_NONPROFIT_FORM_AVAILABLE=YES`
- `BTRUST_PROVIDER_ENDPOINT_AUTOMATION_AUTHORIZED=NO` until provider response.
- `OFFLINE_PDF_CMS_SESSION_IMPLEMENTED=NO`; **hard blocker** for manual
  B-T embedding even when `.tsr` is fetched.
- `QUALIFIED_TSA_RESPONSE_IN_FINAL_PDF=NOT_VERIFIED`
- `EIDAS_QUALIFICATION_AT_GENTIME=NOT_VERIFIED`
- `FINAL_EU_DSS_PAdES_B_T_LT_LTA=NOT_VERIFIED`
- `RELEASE_READY=NO`

Independent EU DSS documentation describes timestamp qualification as
`QTSA`, `TSA`, or `N/A`; QTSA requires the service's qualified status
in trusted lists at production time. See
https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html

Never replace these independent checks with an instruction to lower
Smart App Control/WDAC, untrusted root stores, revocation checking,
or provider PIN prompts.
