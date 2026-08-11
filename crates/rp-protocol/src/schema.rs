use crate::{
    cbor::{self, CborValue, DecodeError, EncodeError},
    digest::{digest_cbor, Digest, Domain},
    ids::{BootId, DeviceId, IdentifierError, Nonce, PolicyId, RequestId},
    VERSION,
};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchemaError {
    #[error(transparent)]
    Cbor(#[from] DecodeError),
    #[error(transparent)]
    Identifier(#[from] IdentifierError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("protocol version {actual} is unsupported")]
    ProtocolMismatch { actual: u64 },
    #[error("field {field} is missing")]
    MissingField { field: u64 },
    #[error("field {field} is not permitted in this schema")]
    UnknownField { field: u64 },
    #[error("field {field} has the wrong CBOR type")]
    WrongType { field: u64 },
    #[error("field {field} fails a v1 bound or semantic restriction")]
    InvalidField { field: u64 },
    #[error("message root must be an integer-keyed map")]
    RootNotMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    PackageInstall,
}

impl Operation {
    const PACKAGE_INSTALL_CODE: u64 = 1;

    fn from_code(code: u64) -> Result<Self, SchemaError> {
        if code == Self::PACKAGE_INSTALL_CODE {
            Ok(Self::PackageInstall)
        } else {
            Err(SchemaError::InvalidField { field: 12 })
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::PackageInstall => Self::PACKAGE_INSTALL_CODE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationInput {
    pub package_name: String,
}

impl OperationInput {
    /// Validates the single v1 operation input: a native Debian package name.
    pub fn package_install(package_name: impl Into<String>) -> Result<Self, SchemaError> {
        let package_name = package_name.into();
        if !valid_package_name(&package_name) {
            return Err(SchemaError::InvalidField { field: 13 });
        }
        Ok(Self { package_name })
    }

    fn to_cbor(&self) -> CborValue {
        // Nested schema fields are integer-keyed for the same deterministic
        // profile as the enclosing security-critical message.
        CborValue::Map(vec![(CborValue::Unsigned(1), CborValue::Text(self.package_name.clone()))])
    }

    fn from_cbor(value: CborValue) -> Result<Self, SchemaError> {
        let mut fields = fields(value)?;
        reject_unknown(&fields, &[1])?;
        let package_name = required_text(&mut fields, 1, 255)?;
        if !valid_package_name(&package_name) {
            return Err(SchemaError::InvalidField { field: 13 });
        }
        Ok(Self { package_name })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny,
}

impl Decision {
    fn from_code(code: u64) -> Result<Self, SchemaError> {
        match code {
            1 => Ok(Self::Approve),
            2 => Ok(Self::Deny),
            _ => Err(SchemaError::InvalidField { field: 10 }),
        }
    }

    const fn code(self) -> u64 {
        match self {
            Self::Approve => 1,
            Self::Deny => 2,
        }
    }
}

/// Exact RootPermit v1 Request map (Engineering Spec v2 section 4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub request_id: RequestId,
    pub device_id: DeviceId,
    pub broker_epoch: u64,
    pub generation: u64,
    pub created_utc: i64,
    pub expires_utc: i64,
    pub boot_id: BootId,
    pub deadline_mono_ns: u64,
    pub nonce: Nonce,
    pub requester_uid: u64,
    pub operation: Operation,
    pub operation_input: OperationInput,
    pub policy_id: PolicyId,
    pub policy_digest: Digest,
    pub plan_digest: Digest,
    /// The frozen plan's exact normalized projection. Its full semantic schema
    /// is owned by the plan module, but its CBOR form is still recursively
    /// canonical and bounded before it reaches this type.
    pub frozen_plan: CborValue,
    pub agent_note: Option<String>,
}

impl Request {
    #[must_use]
    pub fn to_cbor(&self) -> CborValue {
        let mut entries = vec![
            field(1, CborValue::Unsigned(VERSION)),
            field(2, bytes(self.request_id.as_ref())),
            field(3, bytes(self.device_id.as_ref())),
            field(4, CborValue::Unsigned(self.broker_epoch)),
            field(5, CborValue::Unsigned(self.generation)),
            field(6, signed(self.created_utc)),
            field(7, signed(self.expires_utc)),
            field(8, bytes(self.boot_id.as_ref())),
            field(9, CborValue::Unsigned(self.deadline_mono_ns)),
            field(10, bytes(self.nonce.as_ref())),
            field(11, CborValue::Unsigned(self.requester_uid)),
            field(12, CborValue::Unsigned(self.operation.code())),
            field(13, self.operation_input.to_cbor()),
            field(14, bytes(self.policy_id.as_ref())),
            field(15, bytes(&self.policy_digest)),
            field(16, bytes(&self.plan_digest)),
            field(17, self.frozen_plan.clone()),
        ];
        if let Some(note) = &self.agent_note {
            entries.push(field(18, CborValue::Text(note.clone())));
        }
        CborValue::Map(entries)
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        Ok(cbor::encode(&self.to_cbor())?)
    }

    #[must_use]
    pub fn digest(&self) -> Result<Digest, SchemaError> {
        self.validate()?;
        Ok(digest_cbor(Domain::Request, &self.to_cbor())?)
    }

    /// Checks a locally constructed request with the same schema path used for
    /// inbound bytes, before it can be encoded or hashed for authorization.
    pub fn validate(&self) -> Result<(), SchemaError> {
        let validated = Self::from_cbor(self.to_cbor())?;
        if !matches!(validated.frozen_plan, CborValue::Map(_)) {
            return Err(SchemaError::WrongType { field: 17 });
        }
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<Self, SchemaError> {
        Self::from_cbor(cbor::decode(input)?)
    }

    pub fn from_cbor(value: CborValue) -> Result<Self, SchemaError> {
        let mut fields = fields(value)?;
        reject_unknown(&fields, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])?;
        version(&mut fields)?;
        let request = Self {
            request_id: RequestId::try_from(required_bytes(&mut fields, 2, 16)?.as_slice())?,
            device_id: DeviceId::try_from(required_bytes(&mut fields, 3, 16)?.as_slice())?,
            broker_epoch: required_unsigned(&mut fields, 4)?,
            generation: required_unsigned(&mut fields, 5)?,
            created_utc: required_signed(&mut fields, 6)?,
            expires_utc: required_signed(&mut fields, 7)?,
            boot_id: BootId::try_from(required_bytes(&mut fields, 8, 16)?.as_slice())?,
            deadline_mono_ns: required_unsigned(&mut fields, 9)?,
            nonce: Nonce::try_from(required_bytes(&mut fields, 10, 32)?.as_slice())?,
            requester_uid: required_unsigned(&mut fields, 11)?,
            operation: Operation::from_code(required_unsigned(&mut fields, 12)?)?,
            operation_input: OperationInput::from_cbor(required(&mut fields, 13)?)?,
            policy_id: PolicyId::try_from(required_bytes(&mut fields, 14, 16)?.as_slice())?,
            policy_digest: digest_field(&mut fields, 15)?,
            plan_digest: digest_field(&mut fields, 16)?,
            frozen_plan: required(&mut fields, 17)?,
            agent_note: optional_text(&mut fields, 18, 512)?,
        };
        if request.expires_utc < request.created_utc {
            return Err(SchemaError::InvalidField { field: 7 });
        }
        if !matches!(&request.frozen_plan, CborValue::Map(_)) {
            return Err(SchemaError::WrongType { field: 17 });
        }
        Ok(request)
    }
}

/// Exact RootPermit v1 ApprovalContext map. Both approve and deny use this
/// structure so their WebAuthn challenges cannot be substituted for one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalContext {
    pub request_id: RequestId,
    pub device_id: DeviceId,
    pub broker_epoch: u64,
    pub request_digest: Digest,
    pub generation: u64,
    pub nonce: Nonce,
    pub rp_id: String,
    pub origin: String,
    pub decision: Decision,
    pub expires_utc: i64,
}

impl ApprovalContext {
    #[must_use]
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            field(1, CborValue::Unsigned(VERSION)),
            field(2, bytes(self.request_id.as_ref())),
            field(3, bytes(self.device_id.as_ref())),
            field(4, CborValue::Unsigned(self.broker_epoch)),
            field(5, bytes(&self.request_digest)),
            field(6, CborValue::Unsigned(self.generation)),
            field(7, bytes(self.nonce.as_ref())),
            field(8, CborValue::Text(self.rp_id.clone())),
            field(9, CborValue::Text(self.origin.clone())),
            field(10, CborValue::Unsigned(self.decision.code())),
            field(11, signed(self.expires_utc)),
        ])
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        Ok(cbor::encode(&self.to_cbor())?)
    }

    /// Digest used when a protocol role commits to the decision context.
    #[must_use]
    pub fn digest(&self) -> Result<Digest, SchemaError> {
        self.validate()?;
        Ok(digest_cbor(Domain::Decision, &self.to_cbor())?)
    }

    /// The exact WebAuthn challenge required by v1 section 3.4.
    #[must_use]
    pub fn webauthn_challenge(&self) -> Result<Digest, SchemaError> {
        self.validate()?;
        Ok(digest_cbor(Domain::WebAuthnChallenge, &self.to_cbor())?)
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        Self::from_cbor(self.to_cbor()).map(|_| ())
    }

    pub fn decode(input: &[u8]) -> Result<Self, SchemaError> {
        Self::from_cbor(cbor::decode(input)?)
    }

    pub fn from_cbor(value: CborValue) -> Result<Self, SchemaError> {
        let mut fields = fields(value)?;
        reject_unknown(&fields, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])?;
        version(&mut fields)?;
        Ok(Self {
            request_id: RequestId::try_from(required_bytes(&mut fields, 2, 16)?.as_slice())?,
            device_id: DeviceId::try_from(required_bytes(&mut fields, 3, 16)?.as_slice())?,
            broker_epoch: required_unsigned(&mut fields, 4)?,
            request_digest: digest_field(&mut fields, 5)?,
            generation: required_unsigned(&mut fields, 6)?,
            nonce: Nonce::try_from(required_bytes(&mut fields, 7, 32)?.as_slice())?,
            rp_id: non_empty(required_text(&mut fields, 8, 253)?, 8)?,
            origin: non_empty(required_text(&mut fields, 9, 255)?, 9)?,
            decision: Decision::from_code(required_unsigned(&mut fields, 10)?)?,
            expires_utc: required_signed(&mut fields, 11)?,
        })
    }
}

fn valid_package_name(package_name: &str) -> bool {
    let bytes = package_name.as_bytes();
    (1..=255).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'.' | b'-'))
}

fn field(key: u64, value: CborValue) -> (CborValue, CborValue) {
    (CborValue::Unsigned(key), value)
}

fn bytes(value: &[u8]) -> CborValue {
    CborValue::Bytes(value.to_vec())
}

fn signed(value: i64) -> CborValue {
    if value >= 0 { CborValue::Unsigned(value.unsigned_abs()) } else { CborValue::Negative(value) }
}

fn fields(value: CborValue) -> Result<BTreeMap<u64, CborValue>, SchemaError> {
    let CborValue::Map(entries) = value else { return Err(SchemaError::RootNotMap) };
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        let CborValue::Unsigned(key) = key else { return Err(SchemaError::RootNotMap) };
        if fields.insert(key, value).is_some() {
            // The profile decoder already catches this. Keep the invariant true
            // for callers that construct CborValue directly.
            return Err(SchemaError::InvalidField { field: key });
        }
    }
    Ok(fields)
}

fn reject_unknown(fields: &BTreeMap<u64, CborValue>, known: &[u64]) -> Result<(), SchemaError> {
    for key in fields.keys() {
        if !known.contains(key) {
            return Err(SchemaError::UnknownField { field: *key });
        }
    }
    Ok(())
}

fn required(fields: &mut BTreeMap<u64, CborValue>, field: u64) -> Result<CborValue, SchemaError> {
    fields.remove(&field).ok_or(SchemaError::MissingField { field })
}

fn version(fields: &mut BTreeMap<u64, CborValue>) -> Result<(), SchemaError> {
    let actual = required_unsigned(fields, 1)?;
    if actual == VERSION { Ok(()) } else { Err(SchemaError::ProtocolMismatch { actual }) }
}

fn required_unsigned(fields: &mut BTreeMap<u64, CborValue>, field: u64) -> Result<u64, SchemaError> {
    match required(fields, field)? {
        CborValue::Unsigned(value) => Ok(value),
        _ => Err(SchemaError::WrongType { field }),
    }
}

fn required_signed(fields: &mut BTreeMap<u64, CborValue>, field: u64) -> Result<i64, SchemaError> {
    match required(fields, field)? {
        CborValue::Unsigned(value) => i64::try_from(value).map_err(|_| SchemaError::InvalidField { field }),
        CborValue::Negative(value) => Ok(value),
        _ => Err(SchemaError::WrongType { field }),
    }
}

fn required_bytes(fields: &mut BTreeMap<u64, CborValue>, field: u64, length: usize) -> Result<Vec<u8>, SchemaError> {
    match required(fields, field)? {
        CborValue::Bytes(value) if value.len() == length => Ok(value),
        CborValue::Bytes(_) => Err(SchemaError::InvalidField { field }),
        _ => Err(SchemaError::WrongType { field }),
    }
}

fn digest_field(fields: &mut BTreeMap<u64, CborValue>, field: u64) -> Result<Digest, SchemaError> {
    required_bytes(fields, field, 32)?.try_into().map_err(|_| SchemaError::InvalidField { field })
}

fn required_text(fields: &mut BTreeMap<u64, CborValue>, field: u64, maximum: usize) -> Result<String, SchemaError> {
    match required(fields, field)? {
        CborValue::Text(value) if value.len() <= maximum => Ok(value),
        CborValue::Text(_) => Err(SchemaError::InvalidField { field }),
        _ => Err(SchemaError::WrongType { field }),
    }
}

fn optional_text(fields: &mut BTreeMap<u64, CborValue>, field: u64, maximum: usize) -> Result<Option<String>, SchemaError> {
    if !fields.contains_key(&field) { return Ok(None) }
    required_text(fields, field, maximum).map(Some)
}

fn non_empty(value: String, field: u64) -> Result<String, SchemaError> {
    if value.is_empty() { Err(SchemaError::InvalidField { field }) } else { Ok(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            request_id: RequestId::new([1; 16]),
            device_id: DeviceId::new([2; 16]),
            broker_epoch: 4,
            generation: 5,
            created_utc: 1_725_000_000_000,
            expires_utc: 1_725_000_600_000,
            boot_id: BootId::new([3; 16]),
            deadline_mono_ns: 99,
            nonce: Nonce::new([4; 32]),
            requester_uid: 1_000,
            operation: Operation::PackageInstall,
            operation_input: OperationInput::package_install("ffmpeg").unwrap(),
            policy_id: PolicyId::new([5; 16]),
            policy_digest: [6; 32],
            plan_digest: [7; 32],
            frozen_plan: CborValue::Map(vec![(CborValue::Unsigned(1), CborValue::Text("frozen".into()))]),
            agent_note: Some("install media tools".into()),
        }
    }

    #[test]
    fn request_round_trips_and_is_canonical() {
        let request = request();
        let bytes = request.canonical_bytes().unwrap();
        assert_eq!(Request::decode(&bytes).unwrap(), request);
        assert_eq!(cbor::encode(&Request::decode(&bytes).unwrap().to_cbor()).unwrap(), bytes);
    }

    #[test]
    fn request_rejects_unknown_field() {
        let mut map = request().to_cbor();
        let CborValue::Map(entries) = &mut map else { unreachable!() };
        entries.push(field(19, CborValue::Null));
        assert_eq!(Request::from_cbor(map), Err(SchemaError::UnknownField { field: 19 }));
    }

    #[test]
    fn approval_decisions_have_distinct_challenges() {
        let common = ApprovalContext {
            request_id: RequestId::new([1; 16]), device_id: DeviceId::new([2; 16]), broker_epoch: 1,
            request_digest: [3; 32], generation: 2, nonce: Nonce::new([4; 32]),
            rp_id: "rootpermit.example".into(), origin: "https://rootpermit.example".into(),
            decision: Decision::Approve, expires_utc: 100,
        };
        let mut deny = common.clone();
        deny.decision = Decision::Deny;
        assert_ne!(common.webauthn_challenge().unwrap(), deny.webauthn_challenge().unwrap());
    }
}
