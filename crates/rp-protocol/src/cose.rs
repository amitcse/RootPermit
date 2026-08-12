//! Bounded COSE_Sign1 Ed25519 envelopes for RootPermit protocol objects.
//!
//! This is deliberately a small implementation of the COSE Sign1 profile used
//! by RootPermit, not a general COSE parser.  The only admitted tagged value is
//! tag 18 and every protected header is exact.  In particular, callers cannot
//! select a signing algorithm, supply unprotected headers, or use detached
//! payloads.

use crate::{CborValue, Domain, cbor};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use thiserror::Error;

const COSE_SIGN1_TAG: u64 = 18;
const COSE_ALG_LABEL: u64 = 1;
const COSE_CONTENT_TYPE_LABEL: u64 = 3;
const COSE_KID_LABEL: u64 = 4;
const COSE_EDDSA: i64 = -8;
const MAX_KID_BYTES: usize = 32;
const MIN_KID_BYTES: usize = 8;
const ED25519_SIGNATURE_BYTES: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoseError {
    #[error(transparent)]
    Cbor(#[from] cbor::DecodeError),
    #[error(transparent)]
    Encode(#[from] cbor::EncodeError),
    #[error("COSE object is not a tagged Sign1 envelope")]
    NotSign1,
    #[error("COSE Sign1 structure is malformed")]
    InvalidStructure,
    #[error("COSE protected header is malformed or non-canonical")]
    InvalidProtectedHeader,
    #[error("COSE unprotected header must be empty")]
    UnprotectedHeaderPresent,
    #[error("COSE algorithm must be EdDSA (-8)")]
    UnsupportedAlgorithm,
    #[error("COSE signer key ID must contain 8 through 32 opaque bytes")]
    InvalidKid,
    #[error("COSE content type does not match the expected protocol object")]
    ContentTypeMismatch,
    #[error("COSE signature has an invalid length")]
    InvalidSignatureLength,
    #[error("COSE signature is invalid")]
    InvalidSignature,
    #[error("COSE signing key does not have the required role")]
    KeyRoleMismatch,
    #[error("COSE signing key is outside its validity window")]
    KeyOutsideValidity,
}

/// A root-controlled key purpose. Service online keys must be verified against
/// a root-signed keyset before being represented by [`VerificationKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    Broker,
    ServiceRoot,
    DecisionProof,
    Revocation,
    Enrollment,
}

/// Trusted key material after the caller has verified its broker identity or
/// root-signed service keyset. `not_after_utc` is exclusive.
#[derive(Debug, Clone)]
pub struct VerificationKey {
    pub kid: Vec<u8>,
    pub public_key: VerifyingKey,
    pub not_before_utc: i64,
    pub not_after_utc: i64,
    pub roles: Vec<KeyRole>,
}

impl VerificationKey {
    pub fn new(
        kid: Vec<u8>,
        public_key: VerifyingKey,
        not_before_utc: i64,
        not_after_utc: i64,
        roles: Vec<KeyRole>,
    ) -> Result<Self, CoseError> {
        if !(MIN_KID_BYTES..=MAX_KID_BYTES).contains(&kid.len()) {
            return Err(CoseError::InvalidKid);
        }
        if not_after_utc <= not_before_utc || roles.is_empty() {
            return Err(CoseError::KeyOutsideValidity);
        }
        Ok(Self {
            kid,
            public_key,
            not_before_utc,
            not_after_utc,
            roles,
        })
    }

    fn permits(&self, role: KeyRole, now_utc: i64) -> Result<(), CoseError> {
        if !self.roles.contains(&role) {
            return Err(CoseError::KeyRoleMismatch);
        }
        if now_utc < self.not_before_utc || now_utc >= self.not_after_utc {
            return Err(CoseError::KeyOutsideValidity);
        }
        Ok(())
    }
}

/// The object-specific verification policy. A caller must provide the exact
/// content type and the role that it expects; neither is inferred from a
/// network route or an untrusted envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationPolicy {
    pub content_type: u64,
    pub domain: Domain,
    pub required_role: KeyRole,
    pub now_utc: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1 {
    pub kid: Vec<u8>,
    pub content_type: u64,
    pub payload: Vec<u8>,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
    protected: Vec<u8>,
}

impl CoseSign1 {
    /// Signs a non-detached payload using RFC 9052 `Signature1` and the exact
    /// RootPermit domain label as external authenticated data.
    pub fn sign(
        payload: Vec<u8>,
        kid: Vec<u8>,
        content_type: u64,
        domain: Domain,
        signing_key: &SigningKey,
    ) -> Result<Self, CoseError> {
        validate_kid(&kid)?;
        let protected = protected_bytes(&kid, content_type)?;
        let signature = signing_key
            .sign(&signature_structure(&protected, domain, &payload)?)
            .to_bytes();
        Ok(Self {
            kid,
            content_type,
            payload,
            signature,
            protected,
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoseError> {
        let value = cbor::decode(input)?;
        let CborValue::Tag(tag, tagged) = value else {
            return Err(CoseError::NotSign1);
        };
        if tag != COSE_SIGN1_TAG {
            return Err(CoseError::NotSign1);
        }
        let CborValue::Array(values) = *tagged else {
            return Err(CoseError::InvalidStructure);
        };
        let [protected, unprotected, payload, signature] =
            values.try_into().map_err(|_| CoseError::InvalidStructure)?;
        let CborValue::Bytes(protected) = protected else {
            return Err(CoseError::InvalidStructure);
        };
        let CborValue::Map(unprotected) = unprotected else {
            return Err(CoseError::InvalidStructure);
        };
        if !unprotected.is_empty() {
            return Err(CoseError::UnprotectedHeaderPresent);
        }
        let CborValue::Bytes(payload) = payload else {
            return Err(CoseError::InvalidStructure);
        };
        let CborValue::Bytes(signature) = signature else {
            return Err(CoseError::InvalidStructure);
        };
        let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| CoseError::InvalidSignatureLength)?;
        let (kid, content_type) = parse_protected(&protected)?;
        Ok(Self {
            kid,
            content_type,
            payload,
            signature,
            protected,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        // Re-derive the protected header so a manually constructed public
        // value cannot have a header that disagrees with its exposed fields.
        let protected = protected_bytes(&self.kid, self.content_type)?;
        if self.protected != protected {
            return Err(CoseError::InvalidProtectedHeader);
        }
        Ok(cbor::encode(&CborValue::Tag(
            COSE_SIGN1_TAG,
            Box::new(CborValue::Array(vec![
                CborValue::Bytes(protected),
                CborValue::Map(Vec::new()),
                CborValue::Bytes(self.payload.clone()),
                CborValue::Bytes(self.signature.to_vec()),
            ])),
        ))?)
    }

    /// Validates the exact protected header, signing key ID, role, validity and
    /// Ed25519 signature before returning the payload bytes.
    pub fn verify(
        &self,
        key: &VerificationKey,
        policy: VerificationPolicy,
    ) -> Result<(), CoseError> {
        if self.content_type != policy.content_type {
            return Err(CoseError::ContentTypeMismatch);
        }
        if self.kid != key.kid {
            return Err(CoseError::InvalidKid);
        }
        key.permits(policy.required_role, policy.now_utc)?;
        let signature = Signature::from_bytes(&self.signature);
        key.public_key
            .verify(
                &signature_structure(&self.protected, policy.domain, &self.payload)?,
                &signature,
            )
            .map_err(|_| CoseError::InvalidSignature)
    }
}

fn validate_kid(kid: &[u8]) -> Result<(), CoseError> {
    if !(MIN_KID_BYTES..=MAX_KID_BYTES).contains(&kid.len()) {
        return Err(CoseError::InvalidKid);
    }
    Ok(())
}

fn protected_bytes(kid: &[u8], content_type: u64) -> Result<Vec<u8>, CoseError> {
    validate_kid(kid)?;
    Ok(cbor::encode(&CborValue::Map(vec![
        (
            CborValue::Unsigned(COSE_ALG_LABEL),
            CborValue::Negative(COSE_EDDSA),
        ),
        (
            CborValue::Unsigned(COSE_CONTENT_TYPE_LABEL),
            CborValue::Unsigned(content_type),
        ),
        (
            CborValue::Unsigned(COSE_KID_LABEL),
            CborValue::Bytes(kid.to_vec()),
        ),
    ]))?)
}

fn parse_protected(bytes: &[u8]) -> Result<(Vec<u8>, u64), CoseError> {
    let CborValue::Map(entries) = cbor::decode(bytes)? else {
        return Err(CoseError::InvalidProtectedHeader);
    };
    if entries.len() != 3 {
        return Err(CoseError::InvalidProtectedHeader);
    }
    let mut algorithm = None;
    let mut content_type = None;
    let mut kid = None;
    for (key, value) in entries {
        let CborValue::Unsigned(key) = key else {
            return Err(CoseError::InvalidProtectedHeader);
        };
        match (key, value) {
            (COSE_ALG_LABEL, CborValue::Negative(value)) => algorithm = Some(value),
            (COSE_CONTENT_TYPE_LABEL, CborValue::Unsigned(value)) => content_type = Some(value),
            (COSE_KID_LABEL, CborValue::Bytes(value)) => kid = Some(value),
            _ => return Err(CoseError::InvalidProtectedHeader),
        }
    }
    if algorithm != Some(COSE_EDDSA) {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    let kid = kid.ok_or(CoseError::InvalidProtectedHeader)?;
    validate_kid(&kid)?;
    Ok((kid, content_type.ok_or(CoseError::InvalidProtectedHeader)?))
}

fn signature_structure(
    protected: &[u8],
    domain: Domain,
    payload: &[u8],
) -> Result<Vec<u8>, CoseError> {
    Ok(cbor::encode(&CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(domain.label().to_vec()),
        CborValue::Bytes(payload.to_vec()),
    ]))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn verifier() -> VerificationKey {
        VerificationKey::new(
            vec![9; 8],
            key().verifying_key(),
            10,
            20,
            vec![KeyRole::Broker],
        )
        .unwrap()
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy {
            content_type: 1,
            domain: Domain::Request,
            required_role: KeyRole::Broker,
            now_utc: 15,
        }
    }

    #[test]
    fn sign1_round_trip_binds_payload_and_domain() {
        let envelope =
            CoseSign1::sign(vec![1, 2, 3], vec![9; 8], 1, Domain::Request, &key()).unwrap();
        let decoded = CoseSign1::decode(&envelope.encode().unwrap()).unwrap();
        decoded.verify(&verifier(), policy()).unwrap();
        assert_eq!(decoded.payload, vec![1, 2, 3]);
        assert_eq!(
            decoded.verify(
                &verifier(),
                VerificationPolicy {
                    domain: Domain::Receipt,
                    ..policy()
                }
            ),
            Err(CoseError::InvalidSignature)
        );
    }

    #[test]
    fn verification_rejects_wrong_role_and_expired_key() {
        let envelope = CoseSign1::sign(vec![], vec![9; 8], 1, Domain::Request, &key()).unwrap();
        assert_eq!(
            envelope.verify(
                &verifier(),
                VerificationPolicy {
                    required_role: KeyRole::Revocation,
                    ..policy()
                }
            ),
            Err(CoseError::KeyRoleMismatch)
        );
        assert_eq!(
            envelope.verify(
                &verifier(),
                VerificationPolicy {
                    now_utc: 20,
                    ..policy()
                }
            ),
            Err(CoseError::KeyOutsideValidity)
        );
    }
}
