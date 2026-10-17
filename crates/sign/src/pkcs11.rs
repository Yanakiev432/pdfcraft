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
#[cfg(test)]
mod tests {
    use super::*;

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
