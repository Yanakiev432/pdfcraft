//! Conservative eIDAS evidence accounting.
//! Never infer qualified status from a certificate name or OS trust anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence { Confirmed, Rejected, Unavailable }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qualification { Qualified, NotQualified, Indeterminate }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualificationEvidence {
    pub cryptographic_integrity: Evidence,
    pub certificate_path: Evidence,
    pub revocation: Evidence,
    pub trusted_time: Evidence,
    /// Independently authenticated EU Trusted List evidence at relevant time.
    pub eu_trusted_service: Evidence,
    /// Verified qualified certificate and QSCD evidence at relevant time.
    pub qualified_certificate_and_qscd: Evidence,
}

impl QualificationEvidence {
    /// Missing evidence must never be promoted to a qualified result.
    pub fn assess(self) -> Qualification {
        let checks = [
            self.cryptographic_integrity, self.certificate_path, self.revocation,
            self.trusted_time, self.eu_trusted_service, self.qualified_certificate_and_qscd,
        ];
        if checks.contains(&Evidence::Rejected) {
            Qualification::NotQualified
        } else if checks.iter().all(|e| *e == Evidence::Confirmed) {
            Qualification::Qualified
        } else {
            Qualification::Indeterminate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn confirmed() -> QualificationEvidence {
        QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed,
            certificate_path: Evidence::Confirmed,
            revocation: Evidence::Confirmed,
            trusted_time: Evidence::Confirmed,
            eu_trusted_service: Evidence::Confirmed,
            qualified_certificate_and_qscd: Evidence::Confirmed,
        }
    }
    #[test]
    fn complete_evidence_can_be_qualified() {
        assert_eq!(confirmed().assess(), Qualification::Qualified);
    }
    #[test]
    fn os_trust_does_not_imply_eidas_qualification() {
        let e = QualificationEvidence {
            eu_trusted_service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
            ..confirmed()
        };
        assert_eq!(e.assess(), Qualification::Indeterminate);
    }
    #[test]
    fn missing_revocation_is_not_success() {
        let e = QualificationEvidence { revocation: Evidence::Unavailable, ..confirmed() };
        assert_eq!(e.assess(), Qualification::Indeterminate);
    }
    #[test]
    fn explicit_rejection_overrides_unknown() {
        let e = QualificationEvidence {
            cryptographic_integrity: Evidence::Rejected,
            eu_trusted_service: Evidence::Unavailable,
            ..confirmed()
        };
        assert_eq!(e.assess(), Qualification::NotQualified);
    }
}

/// Build a conservative preliminary evidence report from PdfCraft's existing
/// signature verification. This is NOT an eIDAS qualification decision:
/// trusted-list and QSCD verification require separate authenticated inputs.
pub fn from_signature(info: &crate::pdf::SignatureInfo) -> QualificationEvidence {
    use crate::pdf::Status;
    let has = |message: &str| info.details.iter().any(|d| d.message == message);
    let integrity = match info.status {
        Status::Invalid => Evidence::Unavailable,
        Status::Valid => Evidence::Confirmed,
        Status::Unknown => Evidence::Unavailable,
    };
    let certificate_path = if has("The signer's identity is valid.") {
        Evidence::Confirmed
    } else {
        Evidence::Unavailable
    };
    let revocation = if info.details.iter().any(|d| d.message.starts_with("The signer's certificate has been revoked (")) {
        Evidence::Rejected
    } else if has("The document's embedded revocation information shows that the signer's certificate has not been revoked.") {
        Evidence::Confirmed
    } else {
        Evidence::Unavailable
    };
    QualificationEvidence {
        cryptographic_integrity: integrity,
        certificate_path,
        revocation,
        trusted_time: if info.timestamp_time.is_some() { Evidence::Confirmed } else { Evidence::Unavailable },
        eu_trusted_service: Evidence::Unavailable,
        qualified_certificate_and_qscd: Evidence::Unavailable,
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    #[test]
    fn a_valid_signature_still_requires_eu_evidence() {
        let mut info = crate::pdf::SignatureInfo {
            field: String::new(), signed: true, page: None, rect: None, visible: false,
            signer: None, certificate: None, chain: Vec::new(), date: None,
            signing_time: None, reason: None, location: None, contact: None,
            sub_filter: None, doc_timestamp: false, certify: None, revision: 1,
            signed_len: 0, digest: None, algorithm: None, timestamp: false,
            timestamp_time: None, status: crate::pdf::Status::Valid,
            modification: crate::pdf::Modification::None, details: Vec::new(),
        };
        assert_eq!(from_signature(&info).assess(), Qualification::Indeterminate);
        assert_eq!(from_signature(&info).trusted_time, Evidence::Unavailable);
        info.status = crate::pdf::Status::Invalid;
        assert_eq!(from_signature(&info).assess(), Qualification::Indeterminate);
    }
}
