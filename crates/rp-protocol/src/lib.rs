//! RootPermit v1 protocol primitives.
//!
//! This crate intentionally has no permissive CBOR deserialization entry point.
//! Security-critical messages must pass through the bounded, deterministic profile
//! before a schema decoder can inspect them.

#![forbid(unsafe_code)]
// The protocol surface is intentionally documentation-heavy and predates the
// workspace's pedantic lint baseline. Keep security warnings denied while the
// API documentation is completed incrementally.
#![allow(
    clippy::doc_markdown,
    clippy::double_must_use,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

pub mod cbor;
pub mod cose;
pub mod digest;
pub mod ids;
pub mod schema;

pub use cbor::{CborLimits, CborValue, DecodeError, EncodeError, decode, encode};
pub use cose::{CoseError, CoseSign1, KeyRole, VerificationKey, VerificationPolicy};
pub use digest::{Digest, Domain, digest_cbor};
pub use ids::{
    BootId, DeviceId, IdentifierError, Nonce, PolicyId, ReceiptId, RequestId, ServiceEventId,
};
pub use schema::{
    ApprovalContext, Decision, DecisionSubmission, EnrollmentStatement, LifecycleEvent, Operation,
    OperationInput, PlanManifest, Receipt, Request, RevocationEvent, SchemaError, ServiceKeyset,
};

/// The only protocol version implemented by this crate.
pub const VERSION: u64 = 1;
