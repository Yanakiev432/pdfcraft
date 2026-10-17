//! PKCS#11 signing mechanism selection (cryptoki interoperability layer).
//!
//! This is a mechanism policy, not a token driver. A driver must separately
//! discover slots, authenticate users and perform C_Sign without exporting keys.

use crate::SignError;
use crate::keys::DigestAlg;

/// PKCS#11 CKM_* mechanism numbers from the Cryptoki specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mechanism {
    /// CKM_RSA_PKCS: input must be DER DigestInfo, output is RSA signature.
    RsaPkcs,
    /// CKM_ECDSA: input must be a precomputed digest; output is raw r||s.
    Ecdsa,
}

impl Mechanism {
    pub const fn id(self) -> u64 {
        match self {
            Self::RsaPkcs => 0x0000_0001,
            Self::Ecdsa => 0x0000_1041,
        }
    }
}

/// Construct the exact input for a PKCS#11 C_Sign call.
/// RSA uses CKM_RSA_PKCS with DER DigestInfo to avoid token-dependent hashing.
/// ECDSA uses CKM_ECDSA with the raw message digest.
///
/// The driver must transform CKM_ECDSA's raw r||s output into DER before
/// returning it through PdfCraft's ExternalKey interface.
pub fn signing_input(mechanism: Mechanism, digest: DigestAlg, message: &[u8]) -> Result<Vec<u8>, SignError> {
    let hash = digest.digest(&[message]);
    match mechanism {
        Mechanism::Ecdsa => Ok(hash),
        Mechanism::RsaPkcs => {
            let prefix: &[u8] = match digest {
                DigestAlg::Sha256 => {
                    &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
                }
                DigestAlg::Sha384 => {
                    &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
                }
                DigestAlg::Sha512 => {
                    &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
                }
                _ => return Err(SignError::Unsupported("PKCS#11 RSA signing requires SHA-256, SHA-384 or SHA-512".into())),
            };
            let mut input = Vec::with_capacity(prefix.len() + hash.len());
            input.extend_from_slice(prefix);
            input.extend_from_slice(&hash);
            Ok(input)
        }
    }
}

/// Normalize a raw token signature for CMS embedding.
///
/// PdfCraft already validates supported key types and ECDSA component sizes
/// in PublicKey::store_signature_der; reuse it rather than duplicating ASN.1.
pub fn cms_signature(public: &crate::keys::PublicKey, raw: &[u8]) -> Result<Vec<u8>, SignError> {
    public.store_signature_der(raw)
}
/// A token slot discovered from an explicitly supplied PKCS#11 module.
///
/// Discovery never logs in, reads a private key, or calls C_Sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenSlot {
    pub slot_id: u64,
}

/// Enumerate slots containing tokens using a caller-selected module library.
///
/// Loading a native PKCS#11 module executes vendor code in the process.
/// Only pass an explicitly trusted library path; never accept arbitrary paths
/// from PDF files, identity references, or untrusted remote input.
pub fn discover_slots(module_path: &std::path::Path) -> Result<Vec<TokenSlot>, SignError> {
    if !module_path.is_absolute() || !module_path.is_file() {
        return Err(SignError::Unsupported("PKCS#11 module must be an existing absolute library path".into()));
    }
    let context = cryptoki::context::Pkcs11::new(module_path).map_err(|e| SignError::Crypto(format!("cannot load PKCS#11 module: {e}")))?;
    context
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .map_err(|e| SignError::Crypto(format!("cannot initialize PKCS#11 module: {e}")))?;
    let slots = context.get_slots_with_token().map_err(|e| SignError::Crypto(format!("cannot enumerate PKCS#11 slots: {e}")))?;
    Ok(slots.into_iter().map(|slot| TokenSlot { slot_id: slot.id() }).collect())
}
/// Public X.509 certificate bytes and token-local identity metadata.
/// The DER value is a public certificate, never a private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenCertificate {
    pub slot_id: u64,
    pub key_id: Vec<u8>,
    pub label: Vec<u8>,
    pub der: Vec<u8>,
}

/// List publicly accessible certificate objects without logging in.
///
/// Some devices hide certificates until login; an empty result does not prove
/// that the token has no certificates. Never read private-key attributes here.
pub fn discover_certificates(module_path: &std::path::Path) -> Result<Vec<TokenCertificate>, SignError> {
    use cryptoki::object::{Attribute, AttributeType, ObjectClass};

    if !module_path.is_absolute() || !module_path.is_file() {
        return Err(SignError::Unsupported("PKCS#11 module must be an existing absolute library path".into()));
    }
    let context = cryptoki::context::Pkcs11::new(module_path).map_err(|e| SignError::Crypto(format!("cannot load PKCS#11 module: {e}")))?;
    context
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .map_err(|e| SignError::Crypto(format!("cannot initialize PKCS#11 module: {e}")))?;

    let slots = context.get_slots_with_token().map_err(|e| SignError::Crypto(format!("cannot enumerate PKCS#11 slots: {e}")))?;
    let mut certificates = Vec::new();
    for slot in slots {
        let session = context.open_ro_session(slot).map_err(|e| SignError::Crypto(format!("cannot open PKCS#11 read-only session: {e}")))?;
        let objects = session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            .map_err(|e| SignError::Crypto(format!("cannot find PKCS#11 certificate objects: {e}")))?;
        for object in objects {
            let attrs = session
                .get_attributes(object, &[AttributeType::Id, AttributeType::Label, AttributeType::Value])
                .map_err(|e| SignError::Crypto(format!("cannot read PKCS#11 certificate attributes: {e}")))?;
            let mut key_id = Vec::new();
            let mut label = Vec::new();
            let mut der = Vec::new();
            for attr in attrs {
                match attr {
                    Attribute::Id(v) => key_id = v,
                    Attribute::Label(v) => label = v,
                    Attribute::Value(v) => der = v,
                    _ => {}
                }
            }
            if !der.is_empty() {
                certificates.push(TokenCertificate { slot_id: slot.id(), key_id, label, der });
            }
        }
    }
    Ok(certificates)
}
/// Discover a private-key object by certificate CKA_ID without reading its value.
///
/// This performs only object lookup. A successful match is not evidence that
/// the token permits signing or that user authentication has succeeded.
pub fn matching_private_key_count(module_path: &std::path::Path, slot_id: u64, key_id: &[u8]) -> Result<usize, SignError> {
    use cryptoki::object::{Attribute, ObjectClass};
    if key_id.is_empty() {
        return Err(SignError::Unsupported("PKCS#11 key matching requires a nonempty CKA_ID".into()));
    }
    if !module_path.is_absolute() || !module_path.is_file() {
        return Err(SignError::Unsupported("PKCS#11 module must be an existing absolute library path".into()));
    }
    let context = cryptoki::context::Pkcs11::new(module_path).map_err(|e| SignError::Crypto(format!("cannot load PKCS#11 module: {e}")))?;
    context
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .map_err(|e| SignError::Crypto(format!("cannot initialize PKCS#11 module: {e}")))?;
    let slot = cryptoki::slot::Slot::try_from(slot_id).map_err(|e| SignError::Crypto(format!("invalid PKCS#11 slot ID: {e}")))?;
    let session = context.open_ro_session(slot).map_err(|e| SignError::Crypto(format!("cannot open PKCS#11 read-only session: {e}")))?;
    let matches = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(key_id.to_vec())])
        .map_err(|e| SignError::Crypto(format!("cannot match PKCS#11 private-key objects: {e}")))?;
    Ok(matches.len())
}
/// Sign using the token's protected authentication interface.
///
/// Only trusted module paths should be passed. No PIN is accepted by PdfCraft.
/// Invoking this operation may trigger a token consent or PIN prompt.
/// ECDSA returns raw r||s; normalize using cms_signature before CMS embedding.
pub fn sign_with_protected_authentication(
    module_path: &std::path::Path,
    slot_id: u64,
    key_id: &[u8],
    mechanism: Mechanism,
    digest: DigestAlg,
    message: &[u8],
) -> Result<Vec<u8>, SignError> {
    use cryptoki::object::{Attribute, ObjectClass};
    if key_id.is_empty() {
        return Err(SignError::Unsupported("PKCS#11 signing requires a nonempty CKA_ID".into()));
    }
    if !module_path.is_absolute() || !module_path.is_file() {
        return Err(SignError::Unsupported("PKCS#11 module must be an existing absolute library path".into()));
    }
    let input = signing_input(mechanism, digest, message)?;
    let context = cryptoki::context::Pkcs11::new(module_path).map_err(|e| SignError::Crypto(format!("cannot load PKCS#11 module: {e}")))?;
    context
        .initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .map_err(|e| SignError::Crypto(format!("cannot initialize PKCS#11 module: {e}")))?;
    let slot = cryptoki::slot::Slot::try_from(slot_id).map_err(|e| SignError::Crypto(format!("invalid PKCS#11 slot ID: {e}")))?;
    let token = context.get_token_info(slot).map_err(|e| SignError::Crypto(format!("cannot read PKCS#11 token information: {e}")))?;
    if !token.protected_authentication_path() {
        return Err(SignError::Unsupported("PKCS#11 token has no protected authentication path; application PIN entry is not supported".into()));
    }
    let session = context.open_ro_session(slot).map_err(|e| SignError::Crypto(format!("cannot open PKCS#11 session: {e}")))?;
    session.login(cryptoki::session::UserType::User, None).map_err(|e| SignError::Crypto(format!("PKCS#11 protected authentication failed: {e}")))?;
    let keys = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(key_id.to_vec()), Attribute::Sign(true)])
        .map_err(|e| SignError::Crypto(format!("cannot locate PKCS#11 signing key: {e}")))?;
    let [key] = keys.as_slice() else {
        return Err(SignError::Unsupported("PKCS#11 signing requires exactly one matching signing key".into()));
    };
    let pkcs11_mechanism = match mechanism {
        Mechanism::RsaPkcs => cryptoki::mechanism::Mechanism::RsaPkcs,
        Mechanism::Ecdsa => cryptoki::mechanism::Mechanism::Ecdsa,
    };
    session.sign(&pkcs11_mechanism, *key, &input).map_err(|e| SignError::Crypto(format!("PKCS#11 C_Sign failed: {e}")))
}
/// An explicitly configured PKCS#11 signing adapter.
///
/// The identity is a caller-selected opaque reference, not a module path or PIN.
/// Construction performs no token operation; signing may invoke the token's
/// protected authentication UI. The public key must come from the selected
/// certificate and is used to normalize ECDSA signatures for CMS.
pub struct Pkcs11SigningProvider {
    module_path: std::path::PathBuf,
    slot_id: u64,
    key_id: Vec<u8>,
    identity: crate::providers::IdentityReference,
    mechanism: Mechanism,
    public_key: crate::keys::PublicKey,
}

impl Pkcs11SigningProvider {
    pub fn new(
        module_path: std::path::PathBuf,
        slot_id: u64,
        key_id: Vec<u8>,
        identifier: impl Into<String>,
        public_key: crate::keys::PublicKey,
    ) -> Result<Self, SignError> {
        if !module_path.is_absolute() || !module_path.is_file() || key_id.is_empty() {
            return Err(SignError::Unsupported("PKCS#11 adapter requires an existing absolute module path and nonempty CKA_ID".into()));
        }
        let mechanism = match &public_key {
            crate::keys::PublicKey::Rsa { .. } => Mechanism::RsaPkcs,
            crate::keys::PublicKey::P256(_) | crate::keys::PublicKey::P384(_) => Mechanism::Ecdsa,
            _ => return Err(SignError::Unsupported("PKCS#11 adapter supports RSA, P-256 and P-384 only".into())),
        };
        let identity = crate::providers::IdentityReference::new(crate::providers::ProviderKind::Pkcs11Token, identifier)
            .map_err(|e| SignError::Unsupported(e.into()))?;
        Ok(Self { module_path, slot_id, key_id, identity, mechanism, public_key })
    }
}

impl crate::providers::SigningProvider for Pkcs11SigningProvider {
    fn kind(&self) -> crate::providers::ProviderKind {
        crate::providers::ProviderKind::Pkcs11Token
    }

    fn sign(&self, request: crate::providers::SigningRequest<'_>) -> Result<Vec<u8>, SignError> {
        if request.identity != &self.identity {
            return Err(SignError::Unsupported("PKCS#11 signing identity does not match configured adapter".into()));
        }
        let raw = sign_with_protected_authentication(&self.module_path, self.slot_id, &self.key_id, self.mechanism, request.digest, request.message)?;
        cms_signature(&self.public_key, &raw)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Opt-in read-only integration smoke test. Never uses a private key or PIN.
    ///
    /// Run with PDFCRAFT_TEST_PKCS11_MODULE set to a trusted absolute path
    /// pointing to a disposable software token's PKCS#11 library.
    #[test]
    #[ignore = "requires a separately provisioned disposable PKCS#11 software token"]
    fn opt_in_software_token_read_only_discovery() {
        let path = std::env::var("PDFCRAFT_TEST_PKCS11_MODULE").expect("set PDFCRAFT_TEST_PKCS11_MODULE to a trusted absolute module path");
        let module = std::path::Path::new(&path);
        assert!(module.is_absolute() && module.is_file(), "test module must be an existing absolute file");
        let slots = discover_slots(module).expect("test PKCS#11 module must support slot discovery");
        assert!(!slots.is_empty(), "test module must have an initialized token");
    }
    /// Opt-in public certificate discovery. No PIN, login, or signing.
    #[test]
    #[ignore = "requires an explicitly trusted PKCS#11 module and attached token"]
    fn opt_in_token_public_certificates() {
        let path = std::env::var("PDFCRAFT_TEST_PKCS11_MODULE").expect("set trusted module path");
        let certs = discover_certificates(std::path::Path::new(&path)).expect("read-only certificate discovery must succeed");
        assert!(!certs.is_empty(), "expected at least one publicly visible certificate");
        for cert in &certs {
            assert!(!cert.der.is_empty());
        }
    }
    /// Read-only object lookup; no private key is exported or used.
    #[test]
    #[ignore = "requires trusted attached token and public CKA_ID metadata"]
    fn opt_in_token_certificate_key_id_lookup() {
        let path = std::env::var("PDFCRAFT_TEST_PKCS11_MODULE").expect("set trusted module path");
        let module = std::path::Path::new(&path);
        let certs = discover_certificates(module).expect("public certificate enumeration must succeed");
        assert!(!certs.is_empty(), "expected a publicly visible certificate");
        let mut eligible = 0usize;
        for cert in &certs {
            if cert.key_id.is_empty() {
                continue;
            }
            eligible += 1;
            let count = matching_private_key_count(module, cert.slot_id, &cert.key_id).expect("read-only private-key object lookup must succeed");
            assert!(count <= 1, "ambiguous private-key CKA_ID mapping");
        }
        assert!(eligible > 0, "no public certificate has CKA_ID metadata");
    }
    /// Read-only token authentication capability probe. Never logs in.
    #[test]
    #[ignore = "requires trusted attached PKCS11 token"]
    fn opt_in_token_protected_authentication_capability() {
        let path = std::env::var("PDFCRAFT_TEST_PKCS11_MODULE").expect("set trusted module path");
        let module = std::path::Path::new(&path);
        let context = cryptoki::context::Pkcs11::new(module).expect("load trusted module");
        context.initialize(cryptoki::context::CInitializeArgs::OsThreads).expect("initialize module");
        let slots = context.get_slots_with_token().expect("enumerate token slots");
        assert!(!slots.is_empty(), "no tokens found");
        for slot in slots {
            let token = context.get_token_info(slot).expect("read token info");
            println!("slot={} protected_authentication_path={}", slot.id(), token.protected_authentication_path());
        }
    }
    #[test]
    fn adapter_rejects_unsupported_key_and_empty_identity_without_loading_module() {
        use crate::keys::PublicKey;
        let existing = std::env::current_exe().unwrap();
        assert!(Pkcs11SigningProvider::new(existing.clone(), 0, vec![1], "unsupported", PublicKey::Ed25519(vec![0; 32]),).is_err());
        assert!(Pkcs11SigningProvider::new(existing, 0, vec![1], "", PublicKey::Rsa { n: vec![1], e: vec![1, 0, 1] },).is_err());
    }
    #[test]
    fn adapter_rejects_invalid_configuration_without_loading_module() {
        use crate::keys::PublicKey;
        assert!(
            Pkcs11SigningProvider::new(std::path::PathBuf::from("relative.dll"), 1, vec![1], "test", PublicKey::Rsa { n: vec![1], e: vec![1, 0, 1] })
                .is_err()
        );
        assert!(
            Pkcs11SigningProvider::new(std::path::PathBuf::from("relative.dll"), 1, vec![], "test", PublicKey::Rsa { n: vec![1], e: vec![1, 0, 1] })
                .is_err()
        );
    }

    #[test]
    fn adapter_rejects_identity_mismatch_before_loading_module() {
        use crate::keys::PublicKey;
        use crate::providers::{IdentityReference, ProviderKind, SigningProvider, SigningRequest};
        let existing = std::env::current_exe().unwrap();
        let adapter = Pkcs11SigningProvider::new(existing, 0, vec![1], "configured", PublicKey::Rsa { n: vec![1], e: vec![1, 0, 1] }).unwrap();
        let wrong = IdentityReference::new(ProviderKind::Pkcs11Token, "other").unwrap();
        assert!(adapter.sign(SigningRequest { identity: &wrong, digest: DigestAlg::Sha256, message: b"test" }).is_err());
    }
    #[test]
    fn key_matching_rejects_empty_id_without_loading_vendor_code() {
        let fake_module = std::path::Path::new("untrusted-pkcs11.dll");
        assert!(matching_private_key_count(fake_module, 0, &[]).is_err());
    }

    #[test]
    fn protected_signing_rejects_empty_id_without_loading_vendor_code() {
        let fake_module = std::path::Path::new("untrusted-pkcs11.dll");
        assert!(sign_with_protected_authentication(fake_module, 0, &[], Mechanism::RsaPkcs, DigestAlg::Sha256, b"test").is_err());
    }

    #[test]
    fn protected_signing_rejects_relative_module_before_token_access() {
        assert!(
            sign_with_protected_authentication(std::path::Path::new("untrusted-pkcs11.dll"), 0, &[1], Mechanism::RsaPkcs, DigestAlg::Sha256, b"test")
                .is_err()
        );
    }
    #[test]
    fn discovery_rejects_missing_or_relative_module_paths() {
        assert!(discover_slots(std::path::Path::new("vendor-pkcs11.dll")).is_err());
        let missing = std::env::temp_dir().join("pdfcraft-nonexistent-pkcs11-module-verify.dll");
        assert!(discover_slots(&missing).is_err());
    }
    #[test]
    fn mechanism_ids_match_cryptoki() {
        assert_eq!(Mechanism::RsaPkcs.id(), 0x0000_0001);
        assert_eq!(Mechanism::Ecdsa.id(), 0x0000_1041);
    }

    #[test]
    fn rsa_sha256_digest_info_matches_standard_vector() {
        let encoded = signing_input(Mechanism::RsaPkcs, DigestAlg::Sha256, b"abc").unwrap();
        assert_eq!(encoded.len(), 51);
        assert_eq!(
            &encoded[..19],
            &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,]
        );
        assert_eq!(&encoded[19..], DigestAlg::Sha256.digest(&[b"abc"]));
    }

    #[test]
    fn ecdsa_input_is_digest_and_unsupported_rsa_hash_is_rejected() {
        assert_eq!(signing_input(Mechanism::Ecdsa, DigestAlg::Sha384, b"abc").unwrap(), DigestAlg::Sha384.digest(&[b"abc"]));
        assert!(signing_input(Mechanism::RsaPkcs, DigestAlg::Sha1, b"abc").is_err());
    }
}
