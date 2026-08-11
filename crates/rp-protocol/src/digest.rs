use crate::{cbor, CborValue, EncodeError};
use sha2::{Digest as _, Sha256};

/// A SHA-256 value used by the RootPermit protocol.
pub type Digest = [u8; 32];

/// Normative domain labels from Engineering Spec v1 section 3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Request,
    AptPlan,
    Decision,
    WebAuthnChallenge,
    Enrollment,
    ServiceKeyset,
    DecisionAccepted,
    Revocation,
    Receipt,
}

impl Domain {
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Request => b"rootpermit/v1/request\0",
            Self::AptPlan => b"rootpermit/v1/apt-plan\0",
            Self::Decision => b"rootpermit/v1/decision\0",
            Self::WebAuthnChallenge => b"rootpermit/v1/webauthn.challenge\0",
            Self::Enrollment => b"rootpermit/v1/enrollment\0",
            Self::ServiceKeyset => b"rootpermit/v1/service-keyset\0",
            Self::DecisionAccepted => b"rootpermit/v1/decision-accepted\0",
            Self::Revocation => b"rootpermit/v1/revocation\0",
            Self::Receipt => b"rootpermit/v1/receipt\0",
        }
    }
}

/// Hashes `domain-label || deterministic-CBOR(value)`.
pub fn digest_cbor(domain: Domain, value: &CborValue) -> Result<Digest, EncodeError> {
    let encoded = cbor::encode(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.label());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}
