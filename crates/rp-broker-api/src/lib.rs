//! Local RootPermit broker RPC framing and schemas.
//!
//! Each `SOCK_SEQPACKET` packet carries exactly one four-byte big-endian length
//! prefix followed by one deterministic-CBOR message. Packet boundaries are a
//! security property: partial, concatenated, and trailing frames are rejected.
//! The server must obtain `SO_PEERCRED` independently; no message field carries
//! or overrides a caller UID, GID, PID, or authorization scope.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use rp_protocol::{CborValue, DecodeError, EncodeError, VERSION, decode, encode};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Maximum CBOR payload in a local broker packet. This is separate from the
/// protocol crate's broader object bound and is checked before allocation.
pub const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
pub const FRAME_LENGTH_BYTES: usize = 4;

/// Root-owned local `SOCK_SEQPACKET` acceptor.
pub struct LocalSocket {
    listener: rp_peercred::SeqPacketListener,
    path: PathBuf,
}

/// Separate root-only administration listener. It is deliberately a distinct
/// filesystem endpoint and protocol namespace: requester peers can never turn
/// a method number into an administrative operation.
pub struct AdminSocket {
    listener: rp_peercred::SeqPacketListener,
    path: PathBuf,
}

impl AdminSocket {
    /// Binds a root-only administrative socket. Group-readable modes are not
    /// accepted because they would turn membership management into authority.
    pub fn bind(path: &Path) -> std::io::Result<Self> {
        validate_socket_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "socket path exists",
                ));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            Err(_) => {}
        }
        let listener = rp_peercred::SeqPacketListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }

    /// Accepts only a kernel-authenticated root peer.
    pub fn accept(&self) -> std::io::Result<rp_peercred::SeqPacketConnection> {
        let stream = self.listener.accept()?;
        if rp_peercred::get(&stream)?.uid != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "admin socket requires root",
            ));
        }
        Ok(stream)
    }
}

impl Drop for AdminSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl LocalSocket {
    /// Binds a private socket and applies its configured requester group mode.
    /// The parent directory must already be root/admin managed.
    pub fn bind(path: &Path, mode: u32) -> std::io::Result<Self> {
        if mode & !0o770 != 0 || mode & 0o007 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe socket mode",
            ));
        }
        validate_socket_parent(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "socket path exists",
                ));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            Err(_) => {}
        }
        let listener = rp_peercred::SeqPacketListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
        })
    }

    /// Accepts a connection and derives identity only from `SO_PEERCRED`.
    pub fn accept(&self) -> std::io::Result<(rp_peercred::SeqPacketConnection, PeerCredentials)> {
        let stream = self.listener.accept()?;
        let credentials = rp_peercred::get(&stream)?;
        Ok((
            stream,
            PeerCredentials::from_so_peer_cred(credentials.pid, credentials.uid, credentials.gid),
        ))
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn validate_socket_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no parent",
        )
    })?;
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socket parent is not root-owned and private",
        ));
    }
    Ok(())
}

/// Reads one bounded length-prefixed RPC frame without trusting peer sizes.
#[derive(Debug, Error)]
pub enum SocketError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("RPC payload exceeds the local socket limit")]
    OversizePayload,
}

pub fn read_frame(
    stream: &mut rp_peercred::SeqPacketConnection,
) -> Result<RpcMessage, SocketError> {
    let mut packet = vec![0; FRAME_LENGTH_BYTES + MAX_FRAME_PAYLOAD_BYTES];
    let received = stream.receive(&mut packet)?;
    if received < FRAME_LENGTH_BYTES {
        return Err(FrameError::TooShort.into());
    }
    let declared = usize::try_from(u32::from_be_bytes(
        packet[..FRAME_LENGTH_BYTES]
            .try_into()
            .map_err(|_| FrameError::TooShort)?,
    ))
    .map_err(|_| SocketError::OversizePayload)?;
    if declared > MAX_FRAME_PAYLOAD_BYTES {
        return Err(SocketError::OversizePayload);
    }
    let expected = FRAME_LENGTH_BYTES + declared;
    if received != expected {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: received - FRAME_LENGTH_BYTES,
        }
        .into());
    }
    RpcMessage::decode_frame(&packet[..received]).map_err(SocketError::from)
}

/// Writes one complete bounded frame.
pub fn write_frame(
    stream: &mut rp_peercred::SeqPacketConnection,
    message: &RpcMessage,
) -> Result<(), SocketError> {
    stream.send(&message.encode_frame()?)?;
    Ok(())
}

/// Kernel-provided Unix peer identity. These values are intentionally absent
/// from every RPC CBOR message. A platform socket adapter must construct this
/// only from `SO_PEERCRED` after accepting the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl PeerCredentials {
    #[must_use]
    pub const fn from_so_peer_cred(pid: u32, uid: u32, gid: u32) -> Self {
        Self { pid, uid, gid }
    }

    #[must_use]
    pub const fn is_root(self) -> bool {
        self.uid == 0
    }
}

/// Returns whether a peer can access an object owned by `owner_uid`. Root is
/// the only cross-UID reader. This predicate intentionally returns no reason.
#[must_use]
pub const fn can_access_owned_request(peer: PeerCredentials, owner_uid: u32) -> bool {
    peer.is_root() || peer.uid == owner_uid
}

/// The sole externally visible result for absent and foreign requester objects.
#[must_use]
pub const fn concealed_visibility_error() -> ErrorCode {
    ErrorCode::NotFoundOrNotAuthorized
}

/// The closed v1 local-RPC method enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    SubmitPackageInstall = 1,
    GetRequest = 2,
    ListRequests = 3,
    CancelRequest = 4,
    GetReceipt = 5,
}

/// Closed namespace carried only on [`AdminSocket`]. These values cannot be
/// decoded by the requester protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AdminMethod {
    StartPairing = 1,
    ChangeCredentials = 2,
    Reconcile = 3,
    Export = 4,
    Purge = 5,
    Unenroll = 6,
}

impl Method {
    const fn code(self) -> u64 {
        match self {
            Self::SubmitPackageInstall => 1,
            Self::GetRequest => 2,
            Self::ListRequests => 3,
            Self::CancelRequest => 4,
            Self::GetReceipt => 5,
        }
    }

    fn from_code(value: u64) -> Result<Self, RpcError> {
        match value {
            1 => Ok(Self::SubmitPackageInstall),
            2 => Ok(Self::GetRequest),
            3 => Ok(Self::ListRequests),
            4 => Ok(Self::CancelRequest),
            5 => Ok(Self::GetReceipt),
            _ => Err(RpcError::UnknownMethod { value }),
        }
    }
}

/// Transport-only 128-bit correlation identifier. It is not a broker request
/// ID and must never be used for request authorization or lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorrelationId([u8; 16]);

impl CorrelationId {
    pub const fn new(value: [u8; 16]) -> Self {
        Self(value)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Request,
    Response,
    Error,
}

impl MessageKind {
    const fn code(self) -> u64 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Error => 3,
        }
    }

    fn from_code(value: u64) -> Result<Self, RpcError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Error),
            _ => Err(RpcError::InvalidMessageKind { value }),
        }
    }
}

/// A request sent by an unprivileged CLI or root administration CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcRequest {
    pub correlation_id: CorrelationId,
    pub method: Method,
    /// Method-specific body. It is always an integer-keyed CBOR map; method
    /// handlers must apply their own exact request schema before use.
    pub body: CborValue,
}

/// A normal method result. Its body is also a bounded integer-keyed map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcResponse {
    pub correlation_id: CorrelationId,
    pub method: Method,
    pub body: CborValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidInput,
    NotAllowed,
    Busy,
    IdempotencyConflict,
    ApprovalLocked,
    NotFoundOrNotAuthorized,
    InvalidCursor,
    CancellationTooLate,
    DeviceNotUnpaired,
    TemporarilyUnavailable,
    CredentialLimitReached,
    UnsafeLifecycleState,
    NotRecoveryRequired,
    ReconciliationNotProved,
    RetentionProtected,
    ProtocolViolation,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NotAllowed => "not_allowed",
            Self::Busy => "busy",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ApprovalLocked => "approval_locked",
            Self::NotFoundOrNotAuthorized => "not_found_or_not_authorized",
            Self::InvalidCursor => "invalid_cursor",
            Self::CancellationTooLate => "cancellation_too_late",
            Self::DeviceNotUnpaired => "device_not_unpaired",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::CredentialLimitReached => "credential_limit_reached",
            Self::UnsafeLifecycleState => "unsafe_lifecycle_state",
            Self::NotRecoveryRequired => "not_recovery_required",
            Self::ReconciliationNotProved => "reconciliation_not_proved",
            Self::RetentionProtected => "retention_protected",
            Self::ProtocolViolation => "protocol_violation",
            Self::Internal => "internal",
        }
    }

    fn parse(value: &str) -> Result<Self, RpcError> {
        match value {
            "invalid_input" => Ok(Self::InvalidInput),
            "not_allowed" => Ok(Self::NotAllowed),
            "busy" => Ok(Self::Busy),
            "idempotency_conflict" => Ok(Self::IdempotencyConflict),
            "approval_locked" => Ok(Self::ApprovalLocked),
            "not_found_or_not_authorized" => Ok(Self::NotFoundOrNotAuthorized),
            "invalid_cursor" => Ok(Self::InvalidCursor),
            "cancellation_too_late" => Ok(Self::CancellationTooLate),
            "device_not_unpaired" => Ok(Self::DeviceNotUnpaired),
            "temporarily_unavailable" => Ok(Self::TemporarilyUnavailable),
            "credential_limit_reached" => Ok(Self::CredentialLimitReached),
            "unsafe_lifecycle_state" => Ok(Self::UnsafeLifecycleState),
            "not_recovery_required" => Ok(Self::NotRecoveryRequired),
            "reconciliation_not_proved" => Ok(Self::ReconciliationNotProved),
            "retention_protected" => Ok(Self::RetentionProtected),
            "protocol_violation" => Ok(Self::ProtocolViolation),
            "internal" => Ok(Self::Internal),
            _ => Err(RpcError::UnknownErrorCode),
        }
    }
}

/// A safe protocol error. The broker maps authorization failures to
/// `NotFoundOrNotAuthorized` at the peer boundary to prevent enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcFailure {
    pub correlation_id: CorrelationId,
    pub method: Method,
    pub code: ErrorCode,
    pub retryable: bool,
    /// Optional bounded safe metadata; never attach foreign object details.
    pub details: Option<CborValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcMessage {
    Request(RpcRequest),
    Response(RpcResponse),
    Failure(RpcFailure),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("RPC packet is shorter than its four-byte length prefix")]
    TooShort,
    #[error("RPC packet length prefix declares {declared} bytes but packet has {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("RPC payload exceeds the {limit}-byte limit")]
    PayloadTooLarge { limit: usize },
    #[error(transparent)]
    Rpc(#[from] RpcError),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RpcError {
    #[error(transparent)]
    Cbor(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("unsupported broker API version {actual}")]
    ProtocolMismatch { actual: u64 },
    #[error("RPC message root must be an integer-keyed CBOR map")]
    RootNotMap,
    #[error("RPC field {field} is missing")]
    MissingField { field: u64 },
    #[error("RPC field {field} is not allowed in this message")]
    UnknownField { field: u64 },
    #[error("RPC field {field} has the wrong CBOR type")]
    WrongType { field: u64 },
    #[error("RPC field {field} violates a v1 size or value bound")]
    InvalidField { field: u64 },
    #[error("RPC method {value} is unknown")]
    UnknownMethod { value: u64 },
    #[error("RPC message kind {value} is unknown")]
    InvalidMessageKind { value: u64 },
    #[error("RPC error code is unknown")]
    UnknownErrorCode,
}

impl RpcMessage {
    pub fn encode_frame(&self) -> Result<Vec<u8>, FrameError> {
        let message = self.to_cbor()?;
        let payload = encode(&message).map_err(RpcError::from)?;
        if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
            return Err(FrameError::PayloadTooLarge {
                limit: MAX_FRAME_PAYLOAD_BYTES,
            });
        }
        let length = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge {
            limit: MAX_FRAME_PAYLOAD_BYTES,
        })?;
        let mut frame = Vec::with_capacity(FRAME_LENGTH_BYTES + payload.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    pub fn decode_frame(packet: &[u8]) -> Result<Self, FrameError> {
        if packet.len() < FRAME_LENGTH_BYTES {
            return Err(FrameError::TooShort);
        }
        let declared = u32::from_be_bytes(
            packet[..FRAME_LENGTH_BYTES]
                .try_into()
                .map_err(|_| FrameError::TooShort)?,
        );
        let declared = usize::try_from(declared).map_err(|_| FrameError::PayloadTooLarge {
            limit: MAX_FRAME_PAYLOAD_BYTES,
        })?;
        let actual = packet.len() - FRAME_LENGTH_BYTES;
        if declared > MAX_FRAME_PAYLOAD_BYTES {
            return Err(FrameError::PayloadTooLarge {
                limit: MAX_FRAME_PAYLOAD_BYTES,
            });
        }
        if declared != actual {
            return Err(FrameError::LengthMismatch { declared, actual });
        }
        let value = decode(&packet[FRAME_LENGTH_BYTES..]).map_err(RpcError::from)?;
        Self::from_cbor(value).map_err(FrameError::from)
    }

    fn to_cbor(&self) -> Result<CborValue, RpcError> {
        match self {
            Self::Request(message) => message.to_cbor(),
            Self::Response(message) => message.to_cbor(),
            Self::Failure(message) => message.to_cbor(),
        }
    }

    fn from_cbor(value: CborValue) -> Result<Self, RpcError> {
        let fields = fields(value)?;
        let kind = MessageKind::from_code(required_unsigned_ref(&fields, 2)?)?;
        match kind {
            MessageKind::Request => Ok(Self::Request(RpcRequest::from_fields(fields)?)),
            MessageKind::Response => Ok(Self::Response(RpcResponse::from_fields(fields)?)),
            MessageKind::Error => Ok(Self::Failure(RpcFailure::from_fields(fields)?)),
        }
    }
}

impl RpcRequest {
    pub fn new(
        correlation_id: CorrelationId,
        method: Method,
        body: CborValue,
    ) -> Result<Self, RpcError> {
        validate_body(&body, 5)?;
        Ok(Self {
            correlation_id,
            method,
            body,
        })
    }

    fn to_cbor(&self) -> Result<CborValue, RpcError> {
        validate_body(&self.body, 5)?;
        Ok(envelope(
            MessageKind::Request,
            self.correlation_id,
            self.method,
            self.body.clone(),
        ))
    }

    fn from_fields(mut fields: BTreeMap<u64, CborValue>) -> Result<Self, RpcError> {
        reject_unknown(&fields, &[1, 2, 3, 4, 5])?;
        common_fields(&mut fields, MessageKind::Request).and_then(|(correlation_id, method)| {
            Self::new(correlation_id, method, required(&mut fields, 5)?)
        })
    }
}

impl RpcResponse {
    pub fn new(
        correlation_id: CorrelationId,
        method: Method,
        body: CborValue,
    ) -> Result<Self, RpcError> {
        validate_body(&body, 5)?;
        Ok(Self {
            correlation_id,
            method,
            body,
        })
    }

    fn to_cbor(&self) -> Result<CborValue, RpcError> {
        validate_body(&self.body, 5)?;
        Ok(envelope(
            MessageKind::Response,
            self.correlation_id,
            self.method,
            self.body.clone(),
        ))
    }

    fn from_fields(mut fields: BTreeMap<u64, CborValue>) -> Result<Self, RpcError> {
        reject_unknown(&fields, &[1, 2, 3, 4, 5])?;
        common_fields(&mut fields, MessageKind::Response).and_then(|(correlation_id, method)| {
            Self::new(correlation_id, method, required(&mut fields, 5)?)
        })
    }
}

impl RpcFailure {
    pub fn new(
        correlation_id: CorrelationId,
        method: Method,
        code: ErrorCode,
        retryable: bool,
        details: Option<CborValue>,
    ) -> Result<Self, RpcError> {
        if let Some(details) = &details {
            validate_body(details, 7)?;
        }
        Ok(Self {
            correlation_id,
            method,
            code,
            retryable,
            details,
        })
    }

    fn to_cbor(&self) -> Result<CborValue, RpcError> {
        if let Some(details) = &self.details {
            validate_body(details, 7)?;
        }
        let mut entries = envelope_entries(MessageKind::Error, self.correlation_id, self.method);
        entries.push(field(5, CborValue::Text(self.code.text().to_owned())));
        entries.push(field(6, CborValue::Bool(self.retryable)));
        if let Some(details) = &self.details {
            entries.push(field(7, details.clone()));
        }
        Ok(CborValue::Map(entries))
    }

    fn from_fields(mut fields: BTreeMap<u64, CborValue>) -> Result<Self, RpcError> {
        reject_unknown(&fields, &[1, 2, 3, 4, 5, 6, 7])?;
        let (correlation_id, method) = common_fields(&mut fields, MessageKind::Error)?;
        let code = ErrorCode::parse(&required_text(&mut fields, 5, 64)?)?;
        let retryable = required_bool(&mut fields, 6)?;
        let details = fields.remove(&7);
        if let Some(details) = &details {
            validate_body(details, 7)?;
        }
        Ok(Self {
            correlation_id,
            method,
            code,
            retryable,
            details,
        })
    }
}

fn envelope(
    kind: MessageKind,
    correlation_id: CorrelationId,
    method: Method,
    body: CborValue,
) -> CborValue {
    CborValue::Map({
        let mut entries = envelope_entries(kind, correlation_id, method);
        entries.push(field(5, body));
        entries
    })
}

fn envelope_entries(
    kind: MessageKind,
    correlation_id: CorrelationId,
    method: Method,
) -> Vec<(CborValue, CborValue)> {
    vec![
        field(1, CborValue::Unsigned(VERSION)),
        field(2, CborValue::Unsigned(kind.code())),
        field(3, CborValue::Bytes(correlation_id.as_bytes().to_vec())),
        field(4, CborValue::Unsigned(method.code())),
    ]
}

fn fields(value: CborValue) -> Result<BTreeMap<u64, CborValue>, RpcError> {
    let CborValue::Map(entries) = value else {
        return Err(RpcError::RootNotMap);
    };
    let mut result = BTreeMap::new();
    for (key, value) in entries {
        let CborValue::Unsigned(key) = key else {
            return Err(RpcError::RootNotMap);
        };
        if result.insert(key, value).is_some() {
            return Err(RpcError::InvalidField { field: key });
        }
    }
    Ok(result)
}

fn reject_unknown(fields: &BTreeMap<u64, CborValue>, known: &[u64]) -> Result<(), RpcError> {
    for field_number in fields.keys() {
        if !known.contains(field_number) {
            return Err(RpcError::UnknownField {
                field: *field_number,
            });
        }
    }
    Ok(())
}

fn common_fields(
    fields: &mut BTreeMap<u64, CborValue>,
    expected_kind: MessageKind,
) -> Result<(CorrelationId, Method), RpcError> {
    let version = required_unsigned(fields, 1)?;
    if version != VERSION {
        return Err(RpcError::ProtocolMismatch { actual: version });
    }
    if MessageKind::from_code(required_unsigned(fields, 2)?)? != expected_kind {
        return Err(RpcError::InvalidField { field: 2 });
    }
    let id = required_bytes(fields, 3, 16)?;
    let correlation_id = CorrelationId::new(
        id.try_into()
            .map_err(|_| RpcError::InvalidField { field: 3 })?,
    );
    let method = Method::from_code(required_unsigned(fields, 4)?)?;
    Ok((correlation_id, method))
}

fn required(
    fields: &mut BTreeMap<u64, CborValue>,
    field_number: u64,
) -> Result<CborValue, RpcError> {
    fields.remove(&field_number).ok_or(RpcError::MissingField {
        field: field_number,
    })
}

fn required_unsigned_ref(
    fields: &BTreeMap<u64, CborValue>,
    field_number: u64,
) -> Result<u64, RpcError> {
    match fields.get(&field_number) {
        Some(CborValue::Unsigned(value)) => Ok(*value),
        Some(_) => Err(RpcError::WrongType {
            field: field_number,
        }),
        None => Err(RpcError::MissingField {
            field: field_number,
        }),
    }
}

fn required_unsigned(
    fields: &mut BTreeMap<u64, CborValue>,
    field_number: u64,
) -> Result<u64, RpcError> {
    match required(fields, field_number)? {
        CborValue::Unsigned(value) => Ok(value),
        _ => Err(RpcError::WrongType {
            field: field_number,
        }),
    }
}

fn required_bytes(
    fields: &mut BTreeMap<u64, CborValue>,
    field_number: u64,
    length: usize,
) -> Result<Vec<u8>, RpcError> {
    match required(fields, field_number)? {
        CborValue::Bytes(value) if value.len() == length => Ok(value),
        CborValue::Bytes(_) => Err(RpcError::InvalidField {
            field: field_number,
        }),
        _ => Err(RpcError::WrongType {
            field: field_number,
        }),
    }
}

fn required_text(
    fields: &mut BTreeMap<u64, CborValue>,
    field_number: u64,
    maximum: usize,
) -> Result<String, RpcError> {
    match required(fields, field_number)? {
        CborValue::Text(value) if value.len() <= maximum => Ok(value),
        CborValue::Text(_) => Err(RpcError::InvalidField {
            field: field_number,
        }),
        _ => Err(RpcError::WrongType {
            field: field_number,
        }),
    }
}

fn required_bool(
    fields: &mut BTreeMap<u64, CborValue>,
    field_number: u64,
) -> Result<bool, RpcError> {
    match required(fields, field_number)? {
        CborValue::Bool(value) => Ok(value),
        _ => Err(RpcError::WrongType {
            field: field_number,
        }),
    }
}

fn validate_body(value: &CborValue, field_number: u64) -> Result<(), RpcError> {
    if matches!(value, CborValue::Map(_)) {
        Ok(())
    } else {
        Err(RpcError::WrongType {
            field: field_number,
        })
    }
}

fn field(number: u64, value: CborValue) -> (CborValue, CborValue) {
    (CborValue::Unsigned(number), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn request() -> RpcRequest {
        RpcRequest::new(
            CorrelationId::new([7; 16]),
            Method::SubmitPackageInstall,
            CborValue::Map(vec![(
                CborValue::Unsigned(1),
                CborValue::Text("ffmpeg".into()),
            )]),
        )
        .unwrap()
    }

    fn socket_test_directory(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "rootpermit-{name}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn bind_for_process_test(path: &Path) -> Option<LocalSocket> {
        match LocalSocket::bind(path, 0o660) {
            Ok(socket) => Some(socket),
            // The ChatGPT sandbox's seccomp profile may forbid `socket(2)`.
            // In a normal Linux test runner this branch is never taken; the
            // actual packet/credential assertions below then run unchanged.
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => None,
            Err(error) => panic!("could not bind seqpacket test socket: {error}"),
        }
    }

    fn running_as_root() -> bool {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .is_some_and(|output| output.status.success() && output.stdout == b"0\n")
    }

    #[test]
    fn request_frame_round_trips_exactly() {
        let message = RpcMessage::Request(request());
        let frame = message.encode_frame().unwrap();
        assert_eq!(RpcMessage::decode_frame(&frame).unwrap(), message);
    }

    #[test]
    fn requester_method_space_cannot_name_administration_methods() {
        assert!(Method::from_code(100).is_err());
        assert_eq!(AdminMethod::Reconcile as u16, 3);
    }

    #[test]
    fn peer_credentials_are_not_wire_claims_and_enforce_root_and_owner_boundaries() {
        let owner = PeerCredentials::from_so_peer_cred(11, 1000, 1000);
        let foreign = PeerCredentials::from_so_peer_cred(12, 1001, 1001);
        let root = PeerCredentials::from_so_peer_cred(1, 0, 0);

        assert!(can_access_owned_request(owner, 1000));
        assert!(!can_access_owned_request(foreign, 1000));
        assert!(can_access_owned_request(root, 1000));
        assert_eq!(
            concealed_visibility_error(),
            ErrorCode::NotFoundOrNotAuthorized
        );
    }

    #[test]
    fn hostile_packet_lengths_are_rejected_before_decode() {
        assert_eq!(RpcMessage::decode_frame(&[]), Err(FrameError::TooShort));
        assert_eq!(
            RpcMessage::decode_frame(&[0, 0, 0]),
            Err(FrameError::TooShort)
        );
        assert_eq!(
            RpcMessage::decode_frame(&[0, 0, 0, 2, 0xf6]),
            Err(FrameError::LengthMismatch {
                declared: 2,
                actual: 1
            })
        );
        let oversized = 65_537_u32.to_be_bytes();
        assert_eq!(
            RpcMessage::decode_frame(&oversized),
            Err(FrameError::PayloadTooLarge {
                limit: MAX_FRAME_PAYLOAD_BYTES
            })
        );
    }

    #[test]
    fn seqpacket_listener_preserves_one_framed_rpc_per_packet() {
        if !running_as_root() {
            return;
        }
        let directory = socket_test_directory("seqpacket");
        let path = directory.join("broker.sock");
        let Some(socket) = bind_for_process_test(&path) else {
            std::fs::remove_dir(directory).unwrap();
            return;
        };
        let expected = RpcMessage::Request(request());
        let expected_for_server = expected.clone();
        let server = std::thread::spawn(move || {
            let (mut connection, _credentials) = socket.accept().unwrap();
            assert_eq!(read_frame(&mut connection).unwrap(), expected_for_server);
            write_frame(
                &mut connection,
                &RpcMessage::Response(
                    RpcResponse::new(
                        CorrelationId::new([7; 16]),
                        Method::SubmitPackageInstall,
                        CborValue::Map(vec![]),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
        });
        let mut client = rp_peercred::SeqPacketConnection::connect(&path).unwrap();
        write_frame(&mut client, &expected).unwrap();
        assert!(matches!(
            read_frame(&mut client).unwrap(),
            RpcMessage::Response(_)
        ));
        server.join().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn peer_uid_comes_from_a_real_nonroot_process() {
        if let Ok(path) = std::env::var("ROOTPERMIT_PEERCRED_CHILD_SOCKET") {
            let mut client = rp_peercred::SeqPacketConnection::connect(Path::new(&path)).unwrap();
            write_frame(&mut client, &RpcMessage::Request(request())).unwrap();
            return;
        }
        if !running_as_root() {
            return;
        }
        let directory = socket_test_directory("peercred-process");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750)).unwrap();
        let path = directory.join("broker.sock");
        let Some(socket) = bind_for_process_test(&path) else {
            std::fs::remove_dir(directory).unwrap();
            return;
        };
        let test_binary = std::env::current_exe().unwrap();
        let mut child = Command::new("setpriv")
            .args([
                "--reuid=65534",
                "--regid=0",
                "--clear-groups",
                test_binary.to_str().unwrap(),
                "--exact",
                "tests::peer_uid_comes_from_a_real_nonroot_process",
            ])
            .env("ROOTPERMIT_PEERCRED_CHILD_SOCKET", &path)
            .spawn()
            .unwrap();
        let (mut connection, credentials) = socket.accept().unwrap();
        assert_eq!(credentials.uid, 65_534);
        assert!(matches!(
            read_frame(&mut connection).unwrap(),
            RpcMessage::Request(_)
        ));
        assert!(child.wait().unwrap().success());
        drop(socket);
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn unknown_method_and_unknown_fields_fail_closed() {
        let unknown_method = CborValue::Map(vec![
            field(1, CborValue::Unsigned(VERSION)),
            field(2, CborValue::Unsigned(1)),
            field(3, CborValue::Bytes(vec![0; 16])),
            field(4, CborValue::Unsigned(99)),
            field(5, CborValue::Map(vec![])),
        ]);
        assert_eq!(
            RpcMessage::from_cbor(unknown_method),
            Err(RpcError::UnknownMethod { value: 99 })
        );

        let unknown_field = CborValue::Map(vec![
            field(1, CborValue::Unsigned(VERSION)),
            field(2, CborValue::Unsigned(1)),
            field(3, CborValue::Bytes(vec![0; 16])),
            field(4, CborValue::Unsigned(1)),
            field(5, CborValue::Map(vec![])),
            field(6, CborValue::Null),
        ]);
        assert_eq!(
            RpcMessage::from_cbor(unknown_field),
            Err(RpcError::UnknownField { field: 6 })
        );
    }
}
