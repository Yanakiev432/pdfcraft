//! Signing-provider identifiers and capabilities.
//!
//! This module describes integration points without accessing certificates,
//! private keys, PINs, smart cards, or remote signing services.

/// A source of signing identities. This is not an assertion of availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ProviderKind {
    WindowsCng,
    MacosKeychain,
    Pkcs12File,
    Pkcs11Token,
    RemoteSigning,
}

/// Stable provider prefix for user-facing identity references.
impl ProviderKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::WindowsCng => "windows",
            Self::MacosKeychain => "keychain",
            Self::Pkcs12File => "pkcs12",
            Self::Pkcs11Token => "pkcs11",
            Self::RemoteSigning => "remote",
        }
    }

    /// Resolve a supported namespace without accessing the provider.
    pub fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "windows" => Some(Self::WindowsCng),
            "keychain" => Some(Self::MacosKeychain),
            "pkcs12" => Some(Self::Pkcs12File),
            "pkcs11" => Some(Self::Pkcs11Token),
            "remote" => Some(Self::RemoteSigning),
            _ => None,
        }
    }
    /// Whether the provider's private keys are expected to remain external.
    pub const fn external_key(self) -> bool {
        !matches!(self, Self::Pkcs12File)
    }

    /// Whether the provider needs a dedicated implementation beyond the
    /// existing platform and PKCS#12 signing paths.
    pub const fn requires_adapter(self) -> bool {
        matches!(self, Self::Pkcs11Token | Self::RemoteSigning)
    }
}

/// A reference to a provider identity, not a credential or a secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityReference {
    pub provider: ProviderKind,
    pub identifier: String,
}

impl IdentityReference {
    /// Construct a reference without permitting empty or ambiguous identifiers.
    pub fn new(provider: ProviderKind, identifier: impl Into<String>) -> Result<Self, &'static str> {
        let identifier = identifier.into();
        if identifier.is_empty() || identifier.trim() != identifier || identifier.chars().any(char::is_control) {
            return Err("identity identifier must be nonempty and contain no surrounding whitespace or control characters");
        }
        Ok(Self { provider, identifier })
    }

    /// Parse a provider reference, rejecting unknown namespaces and malformed IDs.
    ///
    /// The identifier is opaque: callers must not treat it as a filesystem path,
    /// a token PIN, a credential, or an authenticated remote signing session.
    pub fn parse(reference: &str) -> Result<Self, &'static str> {
        let (prefix, identifier) = reference.split_once(':').ok_or("missing signing provider namespace")?;
        let provider = ProviderKind::from_prefix(prefix).ok_or("unknown signing provider namespace")?;
        Self::new(provider, identifier)
    }
    /// Format as a namespaced reference for provider routing.
    pub fn display_reference(&self) -> String {
        format!("{}:{}", self.provider.prefix(), self.identifier)
    }
}

/// A transport-neutral signing request for external key providers.
///
/// The caller supplies message bytes; the provider must hash them according
/// to the selected algorithm, as required by `ExternalKey::sign`.
/// Never place a PIN, bearer token, or private key in this structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningRequest<'a> {
    pub identity: &'a IdentityReference,
    pub digest: crate::keys::DigestAlg,
    pub message: &'a [u8],
}

/// A provider implementation that can sign without exporting private keys.
///
/// PKCS#11 and remote services should implement this trait behind their
/// respective adapters. The trait does not authenticate users or load modules.
pub trait SigningProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;

    /// Return a signature in the same encoding as `ExternalKey::sign`:
    /// RSA PKCS#1 v1.5 bytes, or DER-encoded ECDSA.
    fn sign(&self, request: SigningRequest<'_>) -> Result<Vec<u8>, crate::SignError>;
}

/// A bridge from provider routing to PdfCraft's existing external-key API.
/// Identity references are checked before a provider is invoked.
pub struct ProviderExternalKey {
    identity: IdentityReference,
    provider: std::sync::Arc<dyn SigningProvider>,
}

impl ProviderExternalKey {
    pub fn new(identity: IdentityReference, provider: std::sync::Arc<dyn SigningProvider>) -> Result<Self, crate::SignError> {
        if identity.provider != provider.kind() {
            return Err(crate::SignError::Unsupported("signing identity provider does not match adapter".into()));
        }
        Ok(Self { identity, provider })
    }
}

impl crate::keys::ExternalKey for ProviderExternalKey {
    fn sign(&self, digest: crate::keys::DigestAlg, message: &[u8]) -> Result<Vec<u8>, crate::SignError> {
        self.provider.sign(SigningRequest { identity: &self.identity, digest, message })
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        kind: ProviderKind,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl SigningProvider for MockProvider {
        fn kind(&self) -> ProviderKind {
            self.kind
        }

        fn sign(&self, request: SigningRequest<'_>) -> Result<Vec<u8>, crate::SignError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if request.identity.identifier != "mock-key" {
                return Err(crate::SignError::Crypto("unknown test identity".into()));
            }
            Ok(request.digest.digest(&[request.message]))
        }
    }

    #[test]
    fn external_key_bridge_forwards_bytes_and_digest() {
        use crate::keys::ExternalKey as _;
        let mock = std::sync::Arc::new(MockProvider { kind: ProviderKind::Pkcs11Token, calls: std::sync::atomic::AtomicUsize::new(0) });
        let identity = IdentityReference::new(ProviderKind::Pkcs11Token, "mock-key").unwrap();
        let key = ProviderExternalKey::new(identity, mock.clone()).unwrap();
        let signature = key.sign(crate::keys::DigestAlg::Sha256, b"test message").unwrap();
        assert_eq!(signature, crate::keys::DigestAlg::Sha256.digest(&[b"test message"]));
        assert_eq!(mock.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn provider_mismatch_is_rejected_before_signing() {
        let mock = std::sync::Arc::new(MockProvider { kind: ProviderKind::RemoteSigning, calls: std::sync::atomic::AtomicUsize::new(0) });
        let identity = IdentityReference::new(ProviderKind::Pkcs11Token, "mock-key").unwrap();
        assert!(ProviderExternalKey::new(identity, mock.clone()).is_err());
        assert_eq!(mock.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    #[test]
    fn provider_capabilities_are_explicit() {
        assert!(!ProviderKind::WindowsCng.requires_adapter());
        assert!(!ProviderKind::MacosKeychain.requires_adapter());
        assert!(!ProviderKind::Pkcs12File.external_key());
        assert!(ProviderKind::Pkcs11Token.requires_adapter());
        assert!(ProviderKind::RemoteSigning.requires_adapter());
    }

    #[test]
    fn provider_reference_roundtrip_and_rejections() {
        for provider in
            [ProviderKind::WindowsCng, ProviderKind::MacosKeychain, ProviderKind::Pkcs12File, ProviderKind::Pkcs11Token, ProviderKind::RemoteSigning]
        {
            let id = IdentityReference::new(provider, "cert:01").unwrap();
            assert_eq!(IdentityReference::parse(&id.display_reference()).unwrap(), id);
        }
        assert!(IdentityReference::parse("pkcs11").is_err());
        assert!(IdentityReference::parse("unknown:key").is_err());
        assert!(IdentityReference::parse("pkcs11:").is_err());
        assert!(IdentityReference::parse("pkcs11:key\n").is_err());
    }
    #[test]
    fn references_are_namespaced_without_exposing_secrets() {
        let id = IdentityReference::new(ProviderKind::Pkcs11Token, "slot-1/key-2").unwrap();
        assert_eq!(id.display_reference(), "pkcs11:slot-1/key-2");
        assert!(IdentityReference::new(ProviderKind::WindowsCng, "").is_err());
        assert!(IdentityReference::new(ProviderKind::WindowsCng, " padded ").is_err());
        assert!(IdentityReference::new(ProviderKind::WindowsCng, "line\nbreak").is_err());
    }
}
