//! Strict structural evidence gate for PAdES DSS/VRI.
//! A valid result here is NOT a qualified B-LT result: issuer trust,
//! qualified time and complete historical evidence remain independent gates.
//! The older low-level DSS embed API deliberately does not authenticate input.

use std::sync::Arc;

use pdfcraft_cos::Document;

use crate::dss::{self, Evidence};
use crate::pdf::{self, Status, TrustStore};
use crate::revocation::{CertificateList, OcspResponse, RevocationStatus};
use crate::x509::Certificate;
use crate::{SignError, Time};

const MAX_CERT_DER: usize = 1024 * 1024;
const MAX_CERT_COUNT: usize = 16;
const MAX_EVIDENCE_COUNT: usize = 32;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;

fn reject(message: &str) -> SignError {
    SignError::Pdf(format!("unqualified DSS evidence: {message}"))
}

/// Append an incremental DSS/VRI update only when all provided evidence is
/// structurally valid, cryptographically verifiable, and covers the signer.
///
/// This is NOT a B-LT/QES acceptance decision. The explicitly provided issuer
/// is not authenticated against the EU trusted lists. The provided time does
/// not prove a qualified timestamp. Multiple signatures, chain intermediates
/// and an existing DSS are rejected until evidence mapping is independently
/// authenticated.
pub fn embed_checked(signed_pdf: &[u8], evidence: &Evidence, issuer: &Certificate, at: Time) -> Result<Vec<u8>, SignError> {
    if signed_pdf.is_empty() {
        return Err(reject("empty PDF"));
    }
    if evidence.certs.is_empty() || evidence.certs.len() > MAX_CERT_COUNT || evidence.ocsps.len() + evidence.crls.len() > MAX_EVIDENCE_COUNT {
        return Err(reject("missing certificates or exceeded evidence count limits"));
    }
    let blobs = evidence.certs.iter().chain(&evidence.ocsps).chain(&evidence.crls);
    let mut total = 0usize;
    for blob in blobs {
        total = total.checked_add(blob.len()).ok_or_else(|| reject("evidence byte-count overflow"))?;
        if blob.is_empty() || blob.len() > 2 * MAX_CERT_DER || total > MAX_TOTAL_BYTES {
            return Err(reject("evidence is empty or exceeds size limits"));
        }
    }

    let doc = Document::open(Arc::new(signed_pdf.to_vec()))?;
    let root = doc.root().ok_or_else(|| reject("document has no catalog"))?;
    if doc.get(root).as_dict().is_some_and(|catalog| catalog.get(b"DSS").is_some()) {
        return Err(reject("already contains a DSS; merging previous evidence requires separate authentication"));
    }

    let signatures: Vec<_> = pdf::list(&doc, signed_pdf, &TrustStore { certs: vec![issuer.clone()] }).into_iter().filter(|s| s.signed).collect();
    if signatures.len() != 1 || signatures[0].doc_timestamp || pdf::signature_contents(&doc).len() != 1 {
        return Err(reject("requires exactly one field signature, no document timestamp"));
    }
    let signature = &signatures[0];
    if signature.status != Status::Valid {
        return Err(reject("document signature did not verify against supplied issuer"));
    }
    let signer = signature.certificate.as_ref().ok_or_else(|| reject("signature has no signer certificate"))?;
    if !issuer.may_issue()
        || !issuer.valid_at(at)
        || !signer.valid_at(at)
        || signer.issuer.raw != issuer.subject.raw
        || !signer.signed_by(&issuer.public_key)
    {
        return Err(reject("signer/issuer relationship or validity interval is unverified"));
    }

    let has_signer = evidence.certs.iter().any(|cert| cert.as_slice() == signer.raw);
    let has_issuer = evidence.certs.iter().any(|cert| cert.as_slice() == issuer.raw);
    if !has_signer || !has_issuer {
        return Err(reject("both exact signer and issuer certificate DER must be embedded"));
    }
    for cert_der in &evidence.certs {
        if cert_der.len() > MAX_CERT_DER {
            return Err(reject("certificate DER exceeds size limit"));
        }
        let parsed = Certificate::parse(cert_der).map_err(|_| reject("malformed certificate DER"))?;
        if parsed.raw != signer.raw && parsed.raw != issuer.raw {
            return Err(reject("additional chain certificates need independent validation"));
        }
    }

    let mut good = false;
    for der in &evidence.crls {
        let crl = CertificateList::parse(der).map_err(|_| reject("malformed CRL"))?;
        match crl.check(signer, issuer, at) {
            RevocationStatus::Good => good = true,
            RevocationStatus::Revoked { .. } => return Err(reject("signer revoked according to verified CRL")),
            RevocationStatus::Unknown => return Err(reject("CRL issuer, signature or freshness cannot be verified")),
        }
    }
    for der in &evidence.ocsps {
        let ocsp = OcspResponse::parse(der).map_err(|_| reject("malformed OCSP response"))?;
        match ocsp.check(signer, issuer, at) {
            RevocationStatus::Good => good = true,
            RevocationStatus::Revoked { .. } => return Err(reject("signer revoked according to verified OCSP")),
            RevocationStatus::Unknown => return Err(reject("OCSP issuer, signature or freshness cannot be verified")),
        }
    }
    if !good {
        return Err(reject("no verified non-revoked evidence covering the signer"));
    }

    // The raw DSS writer runs only after these strict checks. EU DSS still
    // supplies the separate actual PAdES/QES acceptance decision.
    dss::embed(&doc, evidence)
}
