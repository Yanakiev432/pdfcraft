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
