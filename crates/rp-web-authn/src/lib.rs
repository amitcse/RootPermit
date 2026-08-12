//! Strict RootPermit WebAuthn assertion-verification boundary.
//!
//! This crate deliberately does **not** parse authenticator data, COSE public
//! keys, DER/ASN.1 signatures, or client-data JSON. Production code provides a
//! reviewed WebAuthn library through [`ReviewedWebAuthnVerifier`]. The small
//! adapter below makes the RootPermit-specific checks explicit and testable:
//! an assertion must bind the broker-created context, exact official origin,
//! RP ID, ES256 credential, user verification, and broker-pinned credential.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::result_unit_err
)]

use rp_protocol::{ApprovalContext, DecisionSubmission, SchemaError};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// The sole COSE credential algorithm accepted in protocol v1.
pub const ES256_ALGORITHM: i64 = -7;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error(transparent)]
    Submission(#[from] SchemaError),
    #[error("submitted approval context differs from the pending broker context")]
    ContextMismatch,
    #[error("credential is not explicitly pinned to the live broker generation")]
    CredentialNotPinned,
    #[error("credential is quarantined")]
    CredentialQuarantined,
    #[error("WebAuthn credential algorithm is not ES256")]
    UnsupportedAlgorithm,
    #[error("reviewed WebAuthn verifier rejected the assertion")]
    AssertionRejected,
    #[error("reviewed verifier returned a credential different from the submitted credential")]
    CredentialMismatch,
    #[error("WebAuthn client data type must be webauthn.get")]
    ClientDataTypeMismatch,
    #[error("WebAuthn challenge does not bind the pending approval context")]
    ChallengeMismatch,
    #[error("WebAuthn origin does not exactly match the broker-pinned origin")]
    OriginMismatch,
    #[error("WebAuthn RP ID hash does not match the broker-pinned RP ID")]
    RpIdMismatch,
    #[error("WebAuthn user-presence flag is missing")]
    UserPresenceMissing,
    #[error("WebAuthn user-verification flag is missing")]
    UserVerificationMissing,
}

/// A root-pinned approval credential. Its public key stays opaque to this
/// adapter and is passed to the reviewed verifier rather than parsed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCredential {
    pub credential_id: Vec<u8>,
    pub generation: u64,
    pub quarantined: bool,
    pub cose_algorithm: i64,
    pub previous_sign_count: u32,
}

impl PinnedCredential {
    #[must_use]
    pub fn active_for(&self, generation: u64) -> bool {
        self.generation == generation && !self.quarantined && self.cose_algorithm == ES256_ALGORITHM
    }
}

/// Facts returned by a reviewed WebAuthn library only after it has parsed and
/// cryptographically verified the supplied assertion with the pinned public
/// key. These are intentionally not accepted from HTTP/CBOR directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryVerifiedAssertion {
    pub credential_id: Vec<u8>,
    pub client_data_type: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub rp_id_hash: [u8; 32],
    pub user_present: bool,
    pub user_verified: bool,
    pub cose_algorithm: i64,
    pub sign_count: u32,
}

/// Boundary implemented by a maintained WebAuthn verification library. The
/// implementation must validate the assertion signature over authenticator
/// data and client-data hash; this crate never reimplements that parsing.
pub trait ReviewedWebAuthnVerifier {
    fn verify_assertion(
        &self,
        submission: &DecisionSubmission,
        credential: &PinnedCredential,
    ) -> Result<LibraryVerifiedAssertion, ()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub credential_id: Vec<u8>,
    pub decision: rp_protocol::Decision,
    pub generation: u64,
    pub sign_count: u32,
    /// An anomaly is audit-only per the v1 spec; a valid, bound assertion is
    /// still eligible for one lifecycle decision.
    pub counter_anomaly: bool,
}

/// Verifies one submitted assertion against a pending broker context. The
/// caller is responsible for the separate lifecycle CAS/single-use transition.
pub fn verify_submission(
    verifier: &impl ReviewedWebAuthnVerifier,
    pending_context: &ApprovalContext,
    pinned_credentials: &[PinnedCredential],
    submission: &DecisionSubmission,
) -> Result<VerifiedAssertion, WebAuthnError> {
    submission.validate()?;
    if &submission.approval_context != pending_context {
        return Err(WebAuthnError::ContextMismatch);
    }
    let pinned = pinned_credentials
        .iter()
        .find(|credential| credential.credential_id == submission.credential_id)
        .ok_or(WebAuthnError::CredentialNotPinned)?;
    if pinned.quarantined {
        return Err(WebAuthnError::CredentialQuarantined);
    }
    if pinned.generation != pending_context.generation {
        return Err(WebAuthnError::CredentialNotPinned);
    }
    if pinned.cose_algorithm != ES256_ALGORITHM {
        return Err(WebAuthnError::UnsupportedAlgorithm);
    }

    let assertion = verifier
        .verify_assertion(submission, pinned)
        .map_err(|()| WebAuthnError::AssertionRejected)?;
    if assertion.credential_id != submission.credential_id {
        return Err(WebAuthnError::CredentialMismatch);
    }
    if assertion.cose_algorithm != ES256_ALGORITHM {
        return Err(WebAuthnError::UnsupportedAlgorithm);
    }
    if assertion.client_data_type != "webauthn.get" {
        return Err(WebAuthnError::ClientDataTypeMismatch);
    }
    if assertion.challenge != pending_context.webauthn_challenge()? {
        return Err(WebAuthnError::ChallengeMismatch);
    }
    if assertion.origin != pending_context.origin {
        return Err(WebAuthnError::OriginMismatch);
    }
    let expected_rp_id_hash: [u8; 32] = Sha256::digest(pending_context.rp_id.as_bytes()).into();
    if assertion.rp_id_hash != expected_rp_id_hash {
        return Err(WebAuthnError::RpIdMismatch);
    }
    if !assertion.user_present {
        return Err(WebAuthnError::UserPresenceMissing);
    }
    if !assertion.user_verified {
        return Err(WebAuthnError::UserVerificationMissing);
    }
    let counter_anomaly = pinned.previous_sign_count != 0
        && assertion.sign_count != 0
        && assertion.sign_count <= pinned.previous_sign_count;
    Ok(VerifiedAssertion {
        credential_id: assertion.credential_id,
        decision: pending_context.decision,
        generation: pending_context.generation,
        sign_count: assertion.sign_count,
        counter_anomaly,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rp_protocol::{Decision, DeviceId, Nonce, RequestId};

    struct FakeVerifier {
        assertion: LibraryVerifiedAssertion,
    }

    impl ReviewedWebAuthnVerifier for FakeVerifier {
        fn verify_assertion(
            &self,
            _: &DecisionSubmission,
            _: &PinnedCredential,
        ) -> Result<LibraryVerifiedAssertion, ()> {
            Ok(self.assertion.clone())
        }
    }

    fn context() -> ApprovalContext {
        ApprovalContext {
            request_id: RequestId::new([1; 16]),
            device_id: DeviceId::new([2; 16]),
            broker_epoch: 3,
            request_digest: [4; 32],
            generation: 5,
            nonce: Nonce::new([6; 32]),
            rp_id: "rootpermit.example".into(),
            origin: "https://rootpermit.example".into(),
            decision: Decision::Approve,
            expires_utc: 7,
        }
    }

    fn submission(context: ApprovalContext) -> DecisionSubmission {
        DecisionSubmission {
            approval_context: context,
            credential_id: vec![8],
            authenticator_data: vec![1],
            client_data_json: br"{}".to_vec(),
            signature: vec![2],
            user_handle: None,
        }
    }

    fn credential() -> PinnedCredential {
        PinnedCredential {
            credential_id: vec![8],
            generation: 5,
            quarantined: false,
            cose_algorithm: ES256_ALGORITHM,
            previous_sign_count: 4,
        }
    }

    fn assertion(context: &ApprovalContext) -> LibraryVerifiedAssertion {
        LibraryVerifiedAssertion {
            credential_id: vec![8],
            client_data_type: "webauthn.get".into(),
            challenge: context.webauthn_challenge().unwrap().to_vec(),
            origin: context.origin.clone(),
            rp_id_hash: Sha256::digest(context.rp_id.as_bytes()).into(),
            user_present: true,
            user_verified: true,
            cose_algorithm: ES256_ALGORITHM,
            sign_count: 5,
        }
    }

    #[test]
    fn accepts_exact_context_and_reports_counter_anomaly_without_denying() {
        let context = context();
        let result = verify_submission(
            &FakeVerifier {
                assertion: assertion(&context),
            },
            &context,
            &[credential()],
            &submission(context.clone()),
        )
        .unwrap();
        assert_eq!(result.decision, Decision::Approve);
        assert!(!result.counter_anomaly);
        let mut anomalous = assertion(&context);
        anomalous.sign_count = 4;
        assert!(
            verify_submission(
                &FakeVerifier {
                    assertion: anomalous
                },
                &context,
                &[credential()],
                &submission(context.clone())
            )
            .unwrap()
            .counter_anomaly
        );
    }

    #[test]
    fn rejects_wrong_origin_rp_uv_and_unpinned_credential() {
        let context = context();
        let mut bad_origin = assertion(&context);
        bad_origin.origin = "https://attacker.example".into();
        assert_eq!(
            verify_submission(
                &FakeVerifier {
                    assertion: bad_origin
                },
                &context,
                &[credential()],
                &submission(context.clone())
            ),
            Err(WebAuthnError::OriginMismatch)
        );
        let mut no_uv = assertion(&context);
        no_uv.user_verified = false;
        assert_eq!(
            verify_submission(
                &FakeVerifier { assertion: no_uv },
                &context,
                &[credential()],
                &submission(context.clone())
            ),
            Err(WebAuthnError::UserVerificationMissing)
        );
        assert_eq!(
            verify_submission(
                &FakeVerifier {
                    assertion: assertion(&context)
                },
                &context,
                &[],
                &submission(context.clone())
            ),
            Err(WebAuthnError::CredentialNotPinned)
        );
    }
}
