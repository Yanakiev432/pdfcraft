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
    // OS trust messages cannot authenticate the complete eIDAS certificate path.
    let certificate_path = Evidence::Unavailable;
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
        assert_eq!(from_signature(&info).certificate_path, Evidence::Unavailable);
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
/// The preliminary PDF report may consume independently verified revocation
/// evidence only after the verifier has authenticated issuer, scope, response
/// signature, certificate identity and a trusted evaluation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevocationProvenance {
    pub issuer_chain_verified: bool,
    pub response_signature_verified: bool,
    pub certificate_identity_verified: bool,
    pub scope_and_freshness_verified: bool,
    pub trusted_evaluation_time: bool,
}

impl RevocationProvenance {
    pub const fn fully_verified(self) -> bool {
        self.issuer_chain_verified && self.response_signature_verified
            && self.certificate_identity_verified && self.scope_and_freshness_verified
            && self.trusted_evaluation_time
    }
}

pub fn with_verified_revocation(
    mut preliminary: QualificationEvidence,
    finding: Evidence,
    provenance: RevocationProvenance,
) -> QualificationEvidence {
    if provenance.fully_verified() {
        preliminary.revocation = finding;
    } else if preliminary.revocation != Evidence::Rejected {
        preliminary.revocation = Evidence::Unavailable;
    }
    preliminary
}

#[cfg(test)]
mod revocation_provenance_tests {
    use super::*;
    fn baseline() -> QualificationEvidence {
        QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed,
            certificate_path: Evidence::Confirmed,
            revocation: Evidence::Unavailable,
            trusted_time: Evidence::Unavailable,
            eu_trusted_service: Evidence::Unavailable,
            qualified_certificate_and_qscd: Evidence::Unavailable,
        }
    }
    fn provenance() -> RevocationProvenance {
        RevocationProvenance {
            issuer_chain_verified: true, response_signature_verified: true,
            certificate_identity_verified: true, scope_and_freshness_verified: true,
            trusted_evaluation_time: true,
        }
    }
    #[test]
    fn all_revocation_provenance_fields_required() {
        let p = provenance();
        assert_eq!(with_verified_revocation(baseline(), Evidence::Confirmed, p).revocation, Evidence::Confirmed);
        let mut cases = [p; 5];
        cases[0].issuer_chain_verified = false;
        cases[1].response_signature_verified = false;
        cases[2].certificate_identity_verified = false;
        cases[3].scope_and_freshness_verified = false;
        cases[4].trusted_evaluation_time = false;
        for missing in cases {
            assert_eq!(with_verified_revocation(baseline(), Evidence::Confirmed, missing).revocation, Evidence::Unavailable);
        }
    }
    #[test]
    fn negative_revocation_is_not_overwritten_by_missing_provenance() {
        let mut e = baseline();
        e.revocation = Evidence::Rejected;
        let mut p = provenance();
        p.trusted_evaluation_time = false;
        assert_eq!(with_verified_revocation(e, Evidence::Confirmed, p).revocation, Evidence::Rejected);
        assert_eq!(with_verified_revocation(baseline(), Evidence::Rejected, provenance()).assess(), Qualification::NotQualified);
    }
}
/// Strict JSON intake for the offline revocation report v1. No JSON field may
/// independently assert trusted chain/time or upgrade qualification.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationReportV1 {
    schema: String,
    evaluation_time_claim: String,
    evaluation_time_trusted: bool,
    issuer_path_verified: bool,
    inputs_sha256: serde_json::Value,
    crl: serde_json::Value,
    ocsp: serde_json::Value,
    combined_observation: String,
    rust_revocation_provenance: RevocationReportProvenance,
    rust_admissible_revocation: String,
    qualification: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationReportProvenance {
    issuer_chain_verified: bool,
    response_signature_verified: bool,
    certificate_identity_verified: bool,
    scope_and_freshness_verified: bool,
    trusted_evaluation_time: bool,
}

/// The report is advisory until an independent native trust/time verifier is
/// wired in. A positive JSON claim cannot authorize a revocation finding.
pub fn from_offline_revocation_report(
    preliminary: QualificationEvidence, json: &str,
) -> Result<QualificationEvidence, String> {
    const MAX_REPORT_BYTES: usize = 262_144;
    if json.len() > MAX_REPORT_BYTES { return Err("revocation report exceeds size limit".into()); }
    let report: RevocationReportV1 = serde_json::from_str(json).map_err(|_| "invalid revocation report schema")?;
    if report.schema != "pdfcraft.eidas.revocation-evidence.v1"
        || report.evaluation_time_claim.is_empty()
        || report.evaluation_time_trusted || report.issuer_path_verified
        || report.rust_revocation_provenance.issuer_chain_verified
        || report.rust_revocation_provenance.trusted_evaluation_time
        || report.rust_admissible_revocation != "Unavailable"
        || report.qualification != "Indeterminate"
        || report.combined_observation.is_empty()
        || !report.inputs_sha256.is_object()
        || !report.crl.is_object() || !report.ocsp.is_object()
    { return Err("untrusted or incompatible revocation report".into()); }
    let _observed = (
        report.rust_revocation_provenance.response_signature_verified,
        report.rust_revocation_provenance.certificate_identity_verified,
        report.rust_revocation_provenance.scope_and_freshness_verified,
    );
    Ok(with_verified_revocation(
        preliminary, Evidence::Unavailable,
        RevocationProvenance {
            issuer_chain_verified: false, response_signature_verified: false,
            certificate_identity_verified: false, scope_and_freshness_verified: false,
            trusted_evaluation_time: false,
        },
    ))
}

#[cfg(test)]
mod offline_report_tests {
    use super::*;
    fn preliminary() -> QualificationEvidence {
        QualificationEvidence {
            cryptographic_integrity: Evidence::Confirmed, certificate_path: Evidence::Unavailable,
            revocation: Evidence::Unavailable, trusted_time: Evidence::Unavailable,
            eu_trusted_service: Evidence::Unavailable, qualified_certificate_and_qscd: Evidence::Unavailable,
        }
    }
    fn report() -> String {
        serde_json::json!({
            "schema":"pdfcraft.eidas.revocation-evidence.v1",
            "evaluation_time_claim":"2026-10-17T20:45:00Z",
            "evaluation_time_trusted":false,"issuer_path_verified":false,
            "inputs_sha256":{},"crl":{},"ocsp":{},
            "combined_observation":"ConcordantGoodAtEvaluationTime",
            "rust_revocation_provenance":{
                "issuer_chain_verified":false,"response_signature_verified":true,
                "certificate_identity_verified":true,"scope_and_freshness_verified":true,
                "trusted_evaluation_time":false
            },
            "rust_admissible_revocation":"Unavailable","qualification":"Indeterminate"
        }).to_string()
    }
    #[test]
    fn valid_report_cannot_promote_qes() {
        let result = from_offline_revocation_report(preliminary(), &report());
        assert!(matches!(result, Ok(e) if e.revocation == Evidence::Unavailable && e.assess() == Qualification::Indeterminate));
    }
    #[test]
    fn forged_trust_flags_are_rejected() {
        for (field, value) in [("evaluation_time_trusted", true), ("issuer_path_verified", true)] {
            let mut doc: serde_json::Value = serde_json::from_str(&report()).unwrap_or_default();
            doc[field] = serde_json::json!(value);
            assert!(from_offline_revocation_report(preliminary(), &doc.to_string()).is_err());
        }
        let mut doc: serde_json::Value = serde_json::from_str(&report()).unwrap_or_default();
        doc["rust_revocation_provenance"]["issuer_chain_verified"] = serde_json::json!(true);
        assert!(from_offline_revocation_report(preliminary(), &doc.to_string()).is_err());
    }
    #[test]
    fn external_python_evidence_report_remains_indeterminate() {
        let Ok(path) = std::env::var("PDFCRAFT_EIDAS_REVOCATION_REPORT") else { return };
        let json = std::fs::read_to_string(path).expect("read test evidence report");
        let result = from_offline_revocation_report(preliminary(), &json).expect("accept report schema");
        assert_eq!(result.revocation, Evidence::Unavailable);
        assert_eq!(result.assess(), Qualification::Indeterminate);
    }

    #[test]
    fn invalid_or_oversized_json_is_rejected() {
        assert!(from_offline_revocation_report(preliminary(), "{}").is_err());
        assert!(from_offline_revocation_report(preliminary(), &"x".repeat(262_145)).is_err());
    }
}