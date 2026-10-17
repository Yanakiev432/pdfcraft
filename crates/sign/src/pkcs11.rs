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
#[cfg(test)]
mod tests {
    use super::*;

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
