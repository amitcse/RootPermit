//! RootPermit v1 protocol primitives.
//!
//! This crate intentionally has no permissive CBOR deserialization entry point.
//! Security-critical messages must pass through the bounded, deterministic profile
//! before a schema decoder can inspect them.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod digest;
pub mod ids;
pub mod schema;

pub use cbor::{decode, encode, CborLimits, CborValue, DecodeError, EncodeError};
pub use digest::{digest_cbor, Domain, Digest};
pub use ids::{BootId, DeviceId, IdentifierError, Nonce, PolicyId, RequestId};
pub use schema::{ApprovalContext, Decision, Operation, OperationInput, Request, SchemaError};

/// The only protocol version implemented by this crate.
pub const VERSION: u64 = 1;
