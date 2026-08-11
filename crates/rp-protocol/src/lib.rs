//! RootPermit v1 protocol primitives.
//!
//! This crate intentionally has no permissive CBOR deserialization entry point.
//! Security-critical messages must pass through the bounded, deterministic profile
//! before a schema decoder can inspect them.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod cose;
pub mod digest;
pub mod ids;
pub mod schema;

pub use cbor::{decode, encode, CborLimits, CborValue, DecodeError, EncodeError};
pub use cose::{CoseError, CoseSign1, KeyRole, VerificationKey, VerificationPolicy};
pub use digest::{digest_cbor, Domain, Digest};
pub use ids::{BootId, DeviceId, IdentifierError, Nonce, PolicyId, ReceiptId, RequestId, ServiceEventId};
pub use schema::{
    ApprovalContext, Decision, DecisionSubmission, EnrollmentStatement, LifecycleEvent, Operation,
    OperationInput, PlanManifest, Receipt, RevocationEvent, SchemaError, ServiceKeyset,
};

/// The only protocol version implemented by this crate.
pub const VERSION: u64 = 1;
