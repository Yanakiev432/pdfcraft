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
        Evidence::Unavailable
    } else {
        Evidence::Unavailable
    };
    QualificationEvidence {
        cryptographic_integrity: integrity,
        certificate_path,
        revocation,
        trusted_time: Evidence::Unavailable, // A parsed timestamp is not proof of an authenticated TSA/time chain.
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

/// External evidence is intentionally not accepted as a boolean or as a CA name.
/// Only a verifier that authenticates the EU LOTL, the national trusted list,
/// the relevant service history and qualifiers may produce this result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedListFinding {
    pub service: Evidence,
    pub qualified_certificate_and_qscd: Evidence,
}

impl TrustedListFinding {
    /// Fail-closed placeholder for callers without an authenticated trusted-list verifier.
    pub const fn unavailable() -> Self {
        Self {
            service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
        }
    }
}

/// Add an authenticated trusted-list finding to a preliminary PDF assessment.
/// A negative or missing cryptographic/revocation finding cannot be overridden.
pub fn with_trusted_list(mut preliminary: QualificationEvidence, finding: TrustedListFinding) -> QualificationEvidence {
    preliminary.eu_trusted_service = finding.service;
    preliminary.qualified_certificate_and_qscd = finding.qualified_certificate_and_qscd;
    preliminary
}

#[cfg(test)]
mod trusted_list_tests {
    use super::*;
    #[test]
    fn no_external_verifier_means_no_qualification() {
        let preliminary = QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed,
            certificate_path: Evidence::Confirmed,
            revocation: Evidence::Confirmed,
            trusted_time: Evidence::Confirmed,
            eu_trusted_service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
        };
        assert_eq!(with_trusted_list(preliminary, TrustedListFinding::unavailable()).assess(), Qualification::Indeterminate);
    }
    #[test]
    fn external_evidence_cannot_override_revocation() {
        let preliminary = QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed,
            certificate_path: Evidence::Confirmed,
            revocation: Evidence::Rejected,
            trusted_time: Evidence::Confirmed,
            eu_trusted_service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
        };
        let finding = TrustedListFinding {
            service: Evidence::Confirmed,
            qualified_certificate_and_qscd: Evidence::Confirmed,
        };
        assert_eq!(with_trusted_list(preliminary, finding).assess(), Qualification::NotQualified);
    }
}

/// Provenance required before a trusted-list result may be used by the
/// qualification engine. This structure does not validate XML signatures:
/// callers must supply evidence from an independently authenticated verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedListProvenance {
    /// EU LOTL authenticity and signer were cryptographically verified.
    pub lotl_signature_verified: bool,
    /// The member-state TL was discovered through that authenticated LOTL.
    pub national_list_link_verified: bool,
    /// National trusted-list signature and signer were verified.
    pub national_list_signature_verified: bool,
    /// Service identity and historical status were matched at validation time.
    pub service_history_verified: bool,
    /// Qualification/QSCD qualifiers were interpreted at validation time.
    pub qualifiers_verified: bool,
}

impl TrustedListProvenance {
    pub const fn fully_verified(self) -> bool {
        self.lotl_signature_verified
            && self.national_list_link_verified
            && self.national_list_signature_verified
            && self.service_history_verified
            && self.qualifiers_verified
    }
}

/// Reject unverifiable provenance even when a caller supplies positive findings.
/// An explicit negative result from authenticated evidence is retained only
/// when every provenance check succeeds.
pub fn with_verified_trusted_list(
    preliminary: QualificationEvidence,
    finding: TrustedListFinding,
    provenance: TrustedListProvenance,
) -> QualificationEvidence {
    if provenance.fully_verified() {
        with_trusted_list(preliminary, finding)
    } else {
        with_trusted_list(preliminary, TrustedListFinding::unavailable())
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    fn provenance() -> TrustedListProvenance {
        TrustedListProvenance {
            lotl_signature_verified: true,
            national_list_link_verified: true,
            national_list_signature_verified: true,
            service_history_verified: true,
            qualifiers_verified: true,
        }
    }
    fn baseline() -> QualificationEvidence {
        QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed,
            certificate_path: Evidence::Confirmed,
            revocation: Evidence::Confirmed,
            trusted_time: Evidence::Confirmed,
            eu_trusted_service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
        }
    }
    fn finding() -> TrustedListFinding {
        TrustedListFinding {
            service: Evidence::Confirmed,
            qualified_certificate_and_qscd: Evidence::Confirmed,
        }
    }
    #[test]
    fn verified_provenance_is_required() {
        assert_eq!(with_verified_trusted_list(baseline(), finding(), provenance()).assess(), Qualification::Qualified);
        let mut p = provenance();
        p.lotl_signature_verified = false;
        assert_eq!(with_verified_trusted_list(baseline(), finding(), p).assess(), Qualification::Indeterminate);
        p = provenance();
        p.national_list_link_verified = false;
        assert_eq!(with_verified_trusted_list(baseline(), finding(), p).assess(), Qualification::Indeterminate);
        p = provenance();
        p.national_list_signature_verified = false;
        assert_eq!(with_verified_trusted_list(baseline(), finding(), p).assess(), Qualification::Indeterminate);
        p = provenance();
        p.service_history_verified = false;
        assert_eq!(with_verified_trusted_list(baseline(), finding(), p).assess(), Qualification::Indeterminate);
        p = provenance();
        p.qualifiers_verified = false;
        assert_eq!(with_verified_trusted_list(baseline(), finding(), p).assess(), Qualification::Indeterminate);
    }
    #[test]
    fn revoked_certificate_cannot_be_overridden() {
        let mut b = baseline();
        b.revocation = Evidence::Rejected;
        assert_eq!(with_verified_trusted_list(b, finding(), provenance()).assess(), Qualification::NotQualified);
    }
}
