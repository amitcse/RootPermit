//! Root-only, SQLite-backed lifecycle authority for the first RootPermit slice.
//!
//! This crate deliberately accepts only a typed Debian binary package name. It
//! owns the request/idempotency state transaction, but it does not plan or
//! execute APT work yet; those responsibilities belong to later M2/M4 layers.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rp_protocol::{
    ApprovalContext, BootId, CborValue, CoseSign1, Decision, DecisionSubmission, DeviceId, Digest,
    Domain, Nonce, Operation, OperationInput, PolicyId, Receipt, ReceiptId, Request, RequestId,
    digest_cbor, encode,
};
use rp_web_authn::{PinnedCredential, ReviewedWebAuthnVerifier, WebAuthnError, verify_submission};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use thiserror::Error;

const MIGRATIONS: [&str; 7] = [
    include_str!("../migrations/0001_initial.sql"),
    include_str!("../migrations/0002_credentials.sql"),
    include_str!("../migrations/0003_identity_receipts.sql"),
    include_str!("../migrations/0004_recovery_holds_active_slot.sql"),
    include_str!("../migrations/0005_persistent_device_identity.sql"),
    include_str!("../migrations/0006_request_binding.sql"),
    include_str!("../migrations/0007_credentials.sql"),
];

/// A kernel-authenticated requester UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequesterUid(u32);

impl RequesterUid {
    /// Creates a requester UID from the value supplied by `SO_PEERCRED`.
    #[must_use]
    pub const fn from_peer_cred(uid: u32) -> Self {
        Self(uid)
    }

    /// Returns the numeric Linux UID for persistence only.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A public RootPermit identifier: exactly 16 random bytes in base64url form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicId(String);

impl PublicId {
    /// Parses a public request identifier without accepting paths or control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, IntakeError> {
        let value = value.into();
        if value.len() != 22 || !value.bytes().all(is_base64url) {
            return Err(IntakeError::InvalidPublicId);
        }
        Ok(Self(value))
    }

    /// Returns the database-safe opaque identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn bytes(&self) -> Result<[u8; 16], BrokerError> {
        URL_SAFE_NO_PAD
            .decode(&self.0)
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(BrokerError::CorruptState)
    }

    /// Generates an opaque random identifier from the operating-system RNG.
    pub fn random() -> Result<Self, BrokerError> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Self::parse(URL_SAFE_NO_PAD.encode(bytes)).map_err(|_| BrokerError::CorruptState)
    }
}

/// Caller-selected key used to make a single package request idempotent.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationKey(String);

impl OperationKey {
    /// Parses a bounded opaque operation key; it is never a shell fragment.
    pub fn parse(value: impl Into<String>) -> Result<Self, IntakeError> {
        let value = value.into();
        if !(16..=128).contains(&value.len()) || !value.bytes().all(is_base64url) {
            return Err(IntakeError::InvalidOperationKey);
        }
        Ok(Self(value))
    }

    /// Returns the opaque key for an equality-only database comparison.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The only v1 agent-controlled operation input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PackageName(String);

impl PackageName {
    /// Parses a base Debian binary package name, excluding architecture, version and flags.
    pub fn parse(value: impl Into<String>) -> Result<Self, IntakeError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if !(2..=64).contains(&bytes.len())
            || !bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !bytes[1..].iter().copied().all(is_package_character)
        {
            return Err(IntakeError::InvalidPackageName);
        }
        Ok(Self(value))
    }

    /// Returns the validated package name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Errors raised before an agent request can influence broker state.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IntakeError {
    /// The request ID is not a 16-byte base64url identifier.
    #[error("request id must be a 16-byte base64url value")]
    InvalidPublicId,
    /// The caller did not supply a bounded opaque idempotency key.
    #[error("operation key must be a 16-128 character base64url value")]
    InvalidOperationKey,
    /// The package name is not a bounded, native Debian binary package name.
    #[error("package name must be 2-64 ASCII Debian binary package-name characters")]
    InvalidPackageName,
}

/// A complete typed input to `package.install`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitPackageInstall {
    /// Fresh public request ID generated by the broker, not the agent.
    pub request_id: PublicId,
    /// Caller identity supplied from `SO_PEERCRED`.
    pub requester_uid: RequesterUid,
    /// Caller retry key.
    pub operation_key: OperationKey,
    /// The sole agent-controlled operation value.
    pub package_name: PackageName,
    /// Credential generation captured when the request begins.
    pub generation: u64,
}

/// Broker-created temporal and policy values that are bound into a pending
/// approval. No field in this structure originates from the requester RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequestContext {
    /// Wall-clock creation time recorded in the signed request.
    pub created_utc: i64,
    /// Wall-clock approval expiry recorded in the signed request.
    pub expires_utc: i64,
    /// Current boot identifier read by the broker at startup.
    pub boot_id: [u8; 16],
    /// Monotonic deadline used for pre-execution expiry checks.
    pub deadline_mono_ns: u64,
    /// Fresh broker nonce used by both approve and deny contexts.
    pub nonce: [u8; 32],
    /// Root-controlled policy identity.
    pub policy_id: [u8; 16],
    /// Digest of the exact root-controlled policy input.
    pub policy_digest: Digest,
}

/// Fixed relying-party values supplied by root-owned broker configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnRelyingParty {
    /// Exact WebAuthn RP ID.
    pub rp_id: String,
    /// Exact approved WebAuthn origin.
    pub origin: String,
}

/// Root-managed credential material. The reviewed verifier owns parsing of
/// `public_key_cose`; the broker only persists it alongside its pin metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPin {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub cose_algorithm: i64,
}

/// Result of one durable WebAuthn decision attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionOutcome {
    pub state: RequestState,
    /// Present only when this decision entered a terminal state.
    pub receipt_cose: Option<Vec<u8>>,
}

/// Policy decision for the one v1 operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The validated package may enter planning.
    Allow,
    /// The package must not create any local request record.
    Deny,
}

/// Root-controlled policy consulted before a request becomes durable.
pub trait PackageInstallPolicy {
    /// Evaluates the package against the locally configured policy.
    fn evaluate(&self, requester_uid: RequesterUid, package_name: &PackageName) -> PolicyDecision;
}

/// Explicit package allowlist policy used by the local broker skeleton and tests.
#[derive(Debug, Clone, Default)]
pub struct PackageAllowlist {
    packages: BTreeSet<PackageName>,
}

impl PackageAllowlist {
    /// Builds an allowlist from already-validated package names.
    #[must_use]
    pub fn new(packages: impl IntoIterator<Item = PackageName>) -> Self {
        Self {
            packages: packages.into_iter().collect(),
        }
    }
}

impl PackageInstallPolicy for PackageAllowlist {
    fn evaluate(&self, _requester_uid: RequesterUid, package_name: &PackageName) -> PolicyDecision {
        if self.packages.contains(package_name) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        }
    }
}

/// Authoritative lifecycle state retained in the broker database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// A typed input has passed policy and awaits the planner.
    Planning,
    /// A frozen signed plan awaits a decision.
    Pending,
    /// A matching approval was accepted exactly once.
    Approved,
    /// The helper has received an execution authorization.
    Executing,
    /// Planning found no package transition.
    NoChange,
    /// Validation or planning rejected the request.
    Invalid,
    /// A matching deny assertion won the lifecycle race.
    Denied,
    /// The local monotonic deadline won the lifecycle race.
    Expired,
    /// The requester cancellation won before execution.
    Cancelled,
    /// The credential generation changed before execution.
    Stale,
    /// The helper proved the exact requested final state.
    Succeeded,
    /// The helper proved a failure without claiming rollback.
    Failed,
    /// A crash or ambiguity requires root reconciliation.
    RecoveryRequired,
}

impl RequestState {
    /// Returns whether this state closes the request and releases the active slot.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::NoChange
                | Self::Invalid
                | Self::Denied
                | Self::Expired
                | Self::Cancelled
                | Self::Stale
                | Self::Succeeded
                | Self::Failed
        )
    }

    /// Returns whether a lifecycle edge is explicitly permitted by v2 section 5.2.
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Planning,
                Self::Pending | Self::NoChange | Self::Invalid
            ) | (
                Self::Pending,
                Self::Approved | Self::Denied | Self::Expired | Self::Cancelled | Self::Stale
            ) | (
                Self::Approved,
                Self::Executing | Self::Cancelled | Self::Stale | Self::Expired
            ) | (
                Self::Executing,
                Self::Succeeded | Self::Failed | Self::RecoveryRequired
            ) | (Self::RecoveryRequired, Self::Succeeded | Self::Failed)
        )
    }

    const fn as_db(self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Executing => "executing",
            Self::NoChange => "no_change",
            Self::Invalid => "invalid",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Stale => "stale",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    fn from_db(value: &str) -> Result<Self, BrokerError> {
        match value {
            "planning" => Ok(Self::Planning),
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "executing" => Ok(Self::Executing),
            "no_change" => Ok(Self::NoChange),
            "invalid" => Ok(Self::Invalid),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            "stale" => Ok(Self::Stale),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "recovery_required" => Ok(Self::RecoveryRequired),
            _ => Err(BrokerError::CorruptState),
        }
    }
}

/// A caller-safe projection of a local request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSummary {
    /// Opaque request ID.
    pub request_id: PublicId,
    /// Requester that owns the idempotency relationship.
    pub requester_uid: RequesterUid,
    /// Current durable lifecycle state.
    pub state: RequestState,
    /// The frozen credential generation boundary.
    pub generation: u64,
}

/// Result of a typed submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// A new request entered `planning`.
    Created(RequestSummary),
    /// The exact `(uid, operation key, input)` retry recovered its original request.
    Existing(RequestSummary),
}

/// Stable broker failures for lifecycle/state authority.
#[derive(Debug, Error)]
pub enum BrokerError {
    /// SQLite rejected or could not persist a state transition.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The package policy rejected the request before any durable state was created.
    #[error("package install is not allowed by local policy")]
    PolicyDenied,
    /// The operation key was reused by one UID with different typed input.
    #[error("operation key was reused with different input")]
    IdempotencyConflict,
    /// A non-terminal request already consumes the one active device slot.
    #[error("a request is already active on this device: {request_id}")]
    Busy {
        /// Opaque request ID that owns the active slot.
        request_id: String,
    },
    /// The caller expected a state that did not win the compare-and-set race.
    #[error("lifecycle compare-and-set lost; current state is {actual:?}")]
    LifecycleRaceLost {
        /// The state observed after the failed CAS.
        actual: RequestState,
    },
    /// The requested edge is not in the v1 lifecycle graph.
    #[error("lifecycle transition from {from:?} to {to:?} is not permitted")]
    InvalidTransition {
        /// Expected source state.
        from: RequestState,
        /// Requested destination state.
        to: RequestState,
    },
    /// No local request exists for the opaque ID.
    #[error("request does not exist")]
    NotFound,
    /// Database data violates a broker-owned invariant.
    #[error("broker database contains an invalid lifecycle value")]
    CorruptState,
    /// SQLite stored an integer that does not fit its security-relevant type.
    #[error("broker database contains an out-of-range numeric value")]
    NumericOutOfRange,
    /// A durable broker file has unsafe ownership, mode, type, or contents.
    #[error("broker durable state has unsafe filesystem metadata")]
    UnsafeFile,
    /// A broker signing key could not be read or written.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The schema is newer than this broker or failed an integrity check.
    #[error("broker database is corrupt or has an unsupported schema")]
    UnsupportedSchema,
    /// A root-only key is missing or has invalid ownership, mode, or bytes.
    #[error("broker signing key has unsafe filesystem metadata or contents")]
    UnsafeKey,
    /// A terminal receipt could not be encoded or signed.
    #[error("broker receipt encoding or signing failed")]
    Receipt,
    /// A reviewed WebAuthn verifier rejected the asserted decision.
    #[error(transparent)]
    WebAuthn(#[from] WebAuthnError),
}

/// Authoritative local state store; no other component may mutate its connection.
pub struct BrokerStore {
    connection: Connection,
    device_id: String,
    device_id_bytes: [u8; 16],
}

/// Root-local Ed25519 identity used exclusively for broker-originated COSE.
/// The seed stays outside SQLite, with the database retaining only its public
/// key and key ID for receipt verification.
#[derive(Debug, Clone)]
pub struct BrokerSigningKey {
    key: SigningKey,
    kid: Vec<u8>,
}

impl BrokerSigningKey {
    /// Opens an existing 32-byte seed or creates one with mode `0600`.
    pub fn load_or_create(path: &Path) -> Result<Self, BrokerError> {
        let exists = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(0o400_000)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != 0
            || metadata.nlink() != 1
        {
            return Err(BrokerError::UnsafeKey);
        }
        let mut seed = [0_u8; 32];
        if exists {
            file.read_exact(&mut seed)?;
            if file.read(&mut [0_u8; 1])? != 0 {
                return Err(BrokerError::UnsafeKey);
            }
        } else {
            File::open("/dev/urandom")?.read_exact(&mut seed)?;
            file.write_all(&seed)?;
            file.sync_all()?;
        }
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let digest: Digest = Sha256::digest(key.verifying_key().as_bytes()).into();
        Self {
            key,
            kid: digest[..16].to_vec(),
        }
    }

    #[must_use]
    pub fn kid(&self) -> &[u8] {
        &self.kid
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl BrokerStore {
    /// Creates an in-memory store for deterministic lifecycle tests.
    pub fn in_memory() -> Result<Self, BrokerError> {
        let connection = Connection::open_in_memory()?;
        Self::from_connection(connection)
    }

    /// Installs broker-owned schema and pragmas on an otherwise private connection.
    pub fn from_connection(connection: Connection) -> Result<Self, BrokerError> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
        )?;
        let version =
            connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?;
        if usize::try_from(version).map_or(true, |value| value > MIGRATIONS.len()) {
            return Err(BrokerError::UnsupportedSchema);
        }
        for (index, migration) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(migration)?;
            transaction.pragma_update(None, "user_version", index + 1)?;
            transaction.commit()?;
        }
        let integrity: String =
            connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if integrity != "ok" {
            return Err(BrokerError::CorruptState);
        }
        let device_id_bytes = connection
            .query_row(
                "SELECT device_id FROM broker_identity WHERE singleton = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|bytes| bytes.try_into().map_err(|_| BrokerError::CorruptState))
            .transpose()?
            .unwrap_or([0; 16]);
        Ok(Self {
            connection,
            device_id: URL_SAFE_NO_PAD.encode(device_id_bytes),
            device_id_bytes,
        })
    }

    /// Pins the current broker public key into durable state. A mismatched key
    /// is an identity reset, not an implicit rotation: callers must stale
    /// outstanding work and perform root-controlled re-enrollment first.
    pub fn initialize_identity(&mut self, signer: &BrokerSigningKey) -> Result<(), BrokerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> = transaction
            .query_row(
                "SELECT key_kid, public_key, device_id FROM broker_identity WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let device_id_bytes = match existing {
            Some((kid, public_key, Some(device_id)))
                if kid == signer.kid && public_key.as_slice() == signer.public_key() =>
            {
                device_id
                    .try_into()
                    .map_err(|_| BrokerError::CorruptState)?
            }
            Some((kid, public_key, None))
                if kid == signer.kid && public_key.as_slice() == signer.public_key() =>
            {
                let device_id = random_bytes_16()?;
                transaction.execute(
                    "UPDATE broker_identity SET device_id = ?1 WHERE singleton = 1",
                    [device_id.as_slice()],
                )?;
                device_id
            }
            Some(_) => return Err(BrokerError::UnsafeKey),
            None => {
                let public_key = signer.public_key();
                let device_id = random_bytes_16()?;
                transaction.execute(
                    "INSERT INTO broker_identity (singleton, key_kid, public_key, broker_epoch, device_id)
                     VALUES (1, ?1, ?2, 0, ?3)",
                    params![signer.kid, public_key.as_slice(), device_id.as_slice()],
                )?;
                device_id
            }
        };
        transaction.commit()?;
        self.device_id = URL_SAFE_NO_PAD.encode(device_id_bytes);
        self.device_id_bytes = device_id_bytes;
        Ok(())
    }

    /// Opens a private durable database, rejecting symlinks and group/world access.
    pub fn open(path: &Path) -> Result<Self, BrokerError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(0o400_000)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != 0
            || metadata.nlink() != 1
        {
            return Err(BrokerError::UnsafeFile);
        }
        // Resolve SQLite through the already checked inode.  Re-opening the
        // original pathname after a metadata check is a TOCTOU bug: a hostile
        // directory writer could substitute a different database in between.
        let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let connection = Connection::open(fd_path)?;
        drop(file);
        Self::from_connection(connection)
    }

    /// Starts a new boot epoch and expires work whose monotonic deadline cannot
    /// safely survive the reboot. Every expiry is evented and receives its
    /// terminal receipt in the same transaction. Executing work is left for
    /// root reconciliation.
    pub fn start_boot(
        &mut self,
        boot_epoch: u64,
        signer: &BrokerSigningKey,
        now_utc: i64,
    ) -> Result<usize, BrokerError> {
        let epoch = i64::try_from(boot_epoch).map_err(|_| BrokerError::NumericOutOfRange)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: i64 = transaction.query_row(
            "SELECT boot_epoch FROM broker_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let changed = if previous == epoch {
            0
        } else {
            ensure_identity(&transaction, signer)?;
            let mut statement = transaction.prepare(
                "SELECT request_id FROM requests
                 WHERE state IN ('planning','pending','approved') AND boot_epoch != ?1",
            )?;
            let request_ids = statement
                .query_map([epoch], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            let mut changed = 0;
            for request_id in request_ids {
                let request_id =
                    PublicId::parse(request_id).map_err(|_| BrokerError::CorruptState)?;
                append_transition(
                    &transaction,
                    &request_id,
                    None,
                    RequestState::Expired,
                    TransitionReason::Expired,
                )?;
                create_receipt(
                    &transaction,
                    &request_id,
                    RequestState::Expired,
                    signer,
                    now_utc,
                    Vec::new(),
                )?;
                changed += 1;
            }
            transaction.execute(
                "UPDATE broker_metadata SET boot_epoch = ?1 WHERE singleton = 1",
                [epoch],
            )?;
            changed
        };
        transaction.commit()?;
        Ok(changed)
    }

    /// Inserts a policy-approved `planning` request or recovers an exact retry.
    pub fn submit(
        &mut self,
        request: SubmitPackageInstall,
        policy: &impl PackageInstallPolicy,
    ) -> Result<SubmitOutcome, BrokerError> {
        if policy.evaluate(request.requester_uid, &request.package_name) == PolicyDecision::Deny {
            return Err(BrokerError::PolicyDenied);
        }

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let digest = input_digest(&request.package_name);
        if let Some(existing) =
            lookup_idempotency(&transaction, request.requester_uid, &request.operation_key)?
        {
            if existing.input_digest == digest {
                transaction.commit()?;
                return Ok(SubmitOutcome::Existing(existing.summary));
            }
            return Err(BrokerError::IdempotencyConflict);
        }

        if let Some(request_id) = transaction
            .query_row(
                "SELECT request_id FROM requests WHERE device_id = ?1 AND state IN ('planning', 'pending', 'approved', 'executing', 'recovery_required') LIMIT 1",
                [self.device_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(BrokerError::Busy { request_id });
        }

        transaction.execute(
            "INSERT INTO requests (request_id, device_id, requester_uid, operation_key, input_digest, package_name, generation, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'planning')",
            params![
                request.request_id.as_str(),
                self.device_id,
                i64::from(request.requester_uid.as_u32()),
                request.operation_key.as_str(),
                digest.as_slice(),
                request.package_name.as_str(),
                i64::try_from(request.generation).map_err(|_| BrokerError::NumericOutOfRange)?,
            ],
        )?;
        let event_digest = lifecycle_event_digest(
            &request.request_id,
            1,
            None,
            RequestState::Planning,
            TransitionReason::Created,
        );
        transaction.execute(
            "INSERT INTO request_events (request_id, sequence, state, reason, previous_event_digest, event_digest)
             VALUES (?1, 1, 'planning', ?2, NULL, ?3)",
            params![request.request_id.as_str(), TransitionReason::Created.code(), event_digest.as_slice()],
        )?;
        transaction.commit()?;
        Ok(SubmitOutcome::Created(RequestSummary {
            request_id: request.request_id,
            requester_uid: request.requester_uid,
            state: RequestState::Planning,
            generation: request.generation,
        }))
    }

    /// Applies a non-terminal lifecycle compare-and-set transition and records
    /// its event. Terminal outcomes must use [`Self::transition_terminal`], so
    /// a durable receipt cannot be skipped by a production caller.
    pub fn transition_nonterminal(
        &mut self,
        request_id: &PublicId,
        expected: RequestState,
        next: RequestState,
    ) -> Result<RequestState, BrokerError> {
        if next.is_terminal() || !expected.permits(next) {
            return Err(BrokerError::InvalidTransition {
                from: expected,
                to: next,
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE requests SET state = ?1 WHERE request_id = ?2 AND state = ?3",
            params![next.as_db(), request_id.as_str(), expected.as_db()],
        )?;
        if changed != 1 {
            let actual = request_state(&transaction, request_id)?;
            return match actual {
                Some(actual) => Err(BrokerError::LifecycleRaceLost { actual }),
                None => Err(BrokerError::NotFound),
            };
        }
        let (sequence, previous_event_digest) = transaction.query_row(
            "SELECT sequence, event_digest FROM request_events WHERE request_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [request_id.as_str()],
            |row| {
                let sequence = row.get::<_, i64>(0)?;
                let digest = row.get::<_, Vec<u8>>(1)?;
                Ok((sequence, digest))
            },
        )?;
        let sequence = u64::try_from(sequence)
            .map_err(|_| BrokerError::NumericOutOfRange)?
            .saturating_add(1);
        let previous_event_digest: Digest = previous_event_digest
            .try_into()
            .map_err(|_| BrokerError::CorruptState)?;
        let reason = transition_reason(next);
        let event_digest = lifecycle_event_digest(
            request_id,
            sequence,
            Some(previous_event_digest),
            next,
            reason,
        );
        transaction.execute(
            "INSERT INTO request_events (request_id, sequence, state, reason, previous_event_digest, event_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request_id.as_str(),
                i64::try_from(sequence).map_err(|_| BrokerError::NumericOutOfRange)?,
                next.as_db(),
                reason.code(),
                previous_event_digest.as_slice(),
                event_digest.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(next)
    }

    /// Freezes the trusted planner output into the exact canonical v1
    /// [`Request`], signs it with the pinned broker identity, and moves the
    /// record to `pending` in the same durable transaction. The requester has
    /// no way to select the plan, nonce, deadline, policy, device identity, or
    /// signed bytes.
    pub fn prepare_for_decision(
        &mut self,
        request_id: &PublicId,
        plan: &FrozenPlan,
        context: &PendingRequestContext,
        signer: &BrokerSigningKey,
    ) -> Result<Vec<u8>, BrokerError> {
        if context.expires_utc < context.created_utc {
            return Err(BrokerError::CorruptState);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_identity(&transaction, signer)?;
        let (requester_uid, package_name, generation): (i64, String, i64) = transaction
            .query_row(
                "SELECT requester_uid, package_name, generation FROM requests
                 WHERE request_id = ?1 AND state = 'planning'",
                [request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| match request_state(&transaction, request_id) {
                Ok(Some(actual)) => BrokerError::LifecycleRaceLost { actual },
                Ok(None) => BrokerError::NotFound,
                Err(error) => error,
            })?;
        if package_name != plan.package_name.as_str() {
            return Err(BrokerError::CorruptState);
        }
        let broker_epoch: i64 = transaction.query_row(
            "SELECT broker_epoch FROM broker_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let request = Request {
            request_id: RequestId::new(request_id.bytes()?),
            device_id: DeviceId::new(self.device_id_bytes),
            broker_epoch: u64::try_from(broker_epoch)
                .map_err(|_| BrokerError::NumericOutOfRange)?,
            generation: u64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)?,
            created_utc: context.created_utc,
            expires_utc: context.expires_utc,
            boot_id: BootId::new(context.boot_id),
            deadline_mono_ns: context.deadline_mono_ns,
            nonce: Nonce::new(context.nonce),
            requester_uid: u64::try_from(requester_uid)
                .map_err(|_| BrokerError::NumericOutOfRange)?,
            operation: Operation::PackageInstall,
            operation_input: OperationInput::package_install(package_name)
                .map_err(|_| BrokerError::CorruptState)?,
            policy_id: PolicyId::new(context.policy_id),
            policy_digest: context.policy_digest,
            plan_digest: plan.plan_digest,
            frozen_plan: plan.to_cbor(),
            agent_note: None,
        };
        let request_digest = request.digest().map_err(|_| BrokerError::Receipt)?;
        let request_payload = request
            .canonical_bytes()
            .map_err(|_| BrokerError::Receipt)?;
        let request_cose = CoseSign1::sign(
            request_payload,
            signer.kid.clone(),
            COSE_CONTENT_TYPE_REQUEST,
            Domain::Request,
            &signer.key,
        )
        .and_then(|envelope| envelope.encode())
        .map_err(|_| BrokerError::Receipt)?;
        let frozen_plan = encode(&request.frozen_plan).map_err(|_| BrokerError::Receipt)?;
        append_transition(
            &transaction,
            request_id,
            Some(RequestState::Planning),
            RequestState::Pending,
            TransitionReason::PlannerPending,
        )?;
        transaction.execute(
            "UPDATE requests SET plan_digest = ?1, request_digest = ?2, request_cose = ?3,
             request_nonce = ?4, request_boot_id = ?5, request_policy_id = ?6,
             request_policy_digest = ?7, request_frozen_plan = ?8, request_expires_utc = ?9,
             deadline_mono_ns = ?10, created_utc = ?11, updated_utc = ?11
             WHERE request_id = ?12",
            params![
                plan.plan_digest.as_slice(),
                request_digest.as_slice(),
                request_cose.as_slice(),
                context.nonce.as_slice(),
                context.boot_id.as_slice(),
                context.policy_id.as_slice(),
                context.policy_digest.as_slice(),
                frozen_plan.as_slice(),
                context.expires_utc,
                i64::try_from(context.deadline_mono_ns)
                    .map_err(|_| BrokerError::NumericOutOfRange)?,
                context.created_utc,
                request_id.as_str(),
            ],
        )?;
        transaction.commit()?;
        Ok(request_cose)
    }

    /// Replaces the complete root-pinned credential set and advances its
    /// generation. This API belongs exclusively behind the administration
    /// endpoint; requester RPCs never carry credential material.
    pub fn replace_credentials(
        &mut self,
        generation: u64,
        credentials: &[CredentialPin],
    ) -> Result<(), BrokerError> {
        if credentials.is_empty()
            || credentials.iter().any(|credential| {
                credential.credential_id.is_empty()
                    || credential.credential_id.len() > 1024
                    || credential.public_key_cose.is_empty()
                    || credential.public_key_cose.len() > 4096
                    || credential.cose_algorithm != rp_web_authn::ES256_ALGORITHM
            })
        {
            return Err(BrokerError::CorruptState);
        }
        let generation = i64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM credentials", [])?;
        for credential in credentials {
            transaction.execute(
                "INSERT INTO credentials (credential_id, generation, cose_algorithm, public_key_cose)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    credential.credential_id,
                    generation,
                    credential.cose_algorithm,
                    credential.public_key_cose,
                ],
            )?;
        }
        transaction.execute(
            "UPDATE broker_metadata SET credential_generation = ?1 WHERE singleton = 1",
            [generation],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Reconstructs the precise broker-created WebAuthn context for one
    /// pending request. The caller selects only which of the two decisions is
    /// being requested; all security-relevant bindings come from SQLite.
    pub fn approval_context(
        &self,
        request_id: &PublicId,
        decision: Decision,
        relying_party: &WebAuthnRelyingParty,
    ) -> Result<ApprovalContext, BrokerError> {
        let (state, generation, request_digest, nonce, expires_utc): (
            String,
            i64,
            Vec<u8>,
            Vec<u8>,
            Option<i64>,
        ) = self.connection.query_row(
            "SELECT state, generation, request_digest, request_nonce, request_expires_utc
                 FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if RequestState::from_db(&state)? != RequestState::Pending {
            return Err(BrokerError::LifecycleRaceLost {
                actual: RequestState::from_db(&state)?,
            });
        }
        let broker_epoch: i64 = self.connection.query_row(
            "SELECT broker_epoch FROM broker_identity WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(ApprovalContext {
            request_id: RequestId::new(request_id.bytes()?),
            device_id: DeviceId::new(self.device_id_bytes),
            broker_epoch: u64::try_from(broker_epoch)
                .map_err(|_| BrokerError::NumericOutOfRange)?,
            request_digest: request_digest
                .try_into()
                .map_err(|_| BrokerError::CorruptState)?,
            generation: u64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)?,
            nonce: Nonce::new(nonce.try_into().map_err(|_| BrokerError::CorruptState)?),
            rp_id: relying_party.rp_id.clone(),
            origin: relying_party.origin.clone(),
            decision,
            expires_utc: expires_utc.ok_or(BrokerError::CorruptState)?,
        })
    }

    /// Verifies a WebAuthn approval or denial with the reviewed verifier, then
    /// rechecks the durable context inside `BEGIN IMMEDIATE` before the single
    /// lifecycle CAS. Expiry and credential-generation changes win first and
    /// are recorded as signed terminal outcomes.
    pub fn apply_webauthn_submission(
        &mut self,
        request_id: &PublicId,
        submission: &DecisionSubmission,
        verifier: &impl ReviewedWebAuthnVerifier,
        relying_party: &WebAuthnRelyingParty,
        signer: &BrokerSigningKey,
        now_mono_ns: u64,
        now_utc: i64,
    ) -> Result<DecisionOutcome, BrokerError> {
        let context = self.approval_context(
            request_id,
            submission.approval_context.decision,
            relying_party,
        )?;
        if context != submission.approval_context {
            return Err(BrokerError::WebAuthn(WebAuthnError::ContextMismatch));
        }
        if now_utc >= context.expires_utc || self.deadline_elapsed(request_id, now_mono_ns)? {
            let receipt = self.transition_terminal(
                request_id,
                RequestState::Pending,
                RequestState::Expired,
                signer,
                now_utc,
            )?;
            return Ok(DecisionOutcome {
                state: RequestState::Expired,
                receipt_cose: Some(receipt),
            });
        }
        let active_generation = self.credential_generation()?;
        if active_generation != context.generation {
            let receipt = self.transition_terminal(
                request_id,
                RequestState::Pending,
                RequestState::Stale,
                signer,
                now_utc,
            )?;
            return Ok(DecisionOutcome {
                state: RequestState::Stale,
                receipt_cose: Some(receipt),
            });
        }
        let credentials = self.pinned_credentials(active_generation)?;
        let verified = verify_submission(verifier, &context, &credentials, submission)?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_identity(&transaction, signer)?;
        let state: String = transaction.query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| row.get(0),
        )?;
        let state = RequestState::from_db(&state)?;
        if state != RequestState::Pending {
            return Err(BrokerError::LifecycleRaceLost { actual: state });
        }
        let current_generation: i64 = transaction.query_row(
            "SELECT credential_generation FROM broker_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if u64::try_from(current_generation).map_err(|_| BrokerError::NumericOutOfRange)?
            != context.generation
        {
            append_transition(
                &transaction,
                request_id,
                Some(RequestState::Pending),
                RequestState::Stale,
                TransitionReason::GenerationStale,
            )?;
            let receipt = create_receipt(
                &transaction,
                request_id,
                RequestState::Stale,
                signer,
                now_utc,
                Vec::new(),
            )?;
            transaction.commit()?;
            return Ok(DecisionOutcome {
                state: RequestState::Stale,
                receipt_cose: Some(receipt),
            });
        }
        let next = match verified.decision {
            Decision::Approve => RequestState::Approved,
            Decision::Deny => RequestState::Denied,
        };
        append_transition(
            &transaction,
            request_id,
            Some(RequestState::Pending),
            next,
            transition_reason(next),
        )?;
        transaction.execute(
            "UPDATE credentials SET sign_count = MAX(sign_count, ?1) WHERE credential_id = ?2",
            params![i64::from(verified.sign_count), verified.credential_id],
        )?;
        let receipt_cose = if next.is_terminal() {
            let evidence = CborValue::Map(vec![
                (
                    CborValue::Unsigned(1),
                    CborValue::Bytes(submission.credential_id.clone()),
                ),
                (
                    CborValue::Unsigned(2),
                    CborValue::Bool(verified.counter_anomaly),
                ),
            ]);
            Some(create_receipt(
                &transaction,
                request_id,
                next,
                signer,
                now_utc,
                vec![evidence],
            )?)
        } else {
            None
        };
        transaction.commit()?;
        Ok(DecisionOutcome {
            state: next,
            receipt_cose,
        })
    }

    /// Applies a terminal state transition and creates the sole broker-signed
    /// COSE receipt in the same SQLite transaction.
    pub fn transition_terminal(
        &mut self,
        request_id: &PublicId,
        expected: RequestState,
        next: RequestState,
        signer: &BrokerSigningKey,
        now_utc: i64,
    ) -> Result<Vec<u8>, BrokerError> {
        self.transition_terminal_with_evidence(
            request_id,
            expected,
            next,
            signer,
            now_utc,
            Vec::new(),
        )
    }

    /// Root-only recovery reconciliation. It accepts a bounded operator
    /// evidence record, cannot restart execution, and is the only durable path
    /// out of `recovery_required`.
    pub fn reconcile_recovery(
        &mut self,
        request_id: &PublicId,
        succeeded: bool,
        operator_evidence: &[u8],
        signer: &BrokerSigningKey,
        now_utc: i64,
    ) -> Result<Vec<u8>, BrokerError> {
        if operator_evidence.is_empty() || operator_evidence.len() > 65_536 {
            return Err(BrokerError::CorruptState);
        }
        let next = if succeeded {
            RequestState::Succeeded
        } else {
            RequestState::Failed
        };
        let reason = if succeeded {
            TransitionReason::ReconciledSucceeded
        } else {
            TransitionReason::ReconciledFailed
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_identity(&transaction, signer)?;
        append_transition(
            &transaction,
            request_id,
            Some(RequestState::RecoveryRequired),
            next,
            reason,
        )?;
        transaction.execute(
            "UPDATE requests SET recovery_evidence = ?1 WHERE request_id = ?2",
            params![operator_evidence, request_id.as_str()],
        )?;
        let cose = create_receipt(&transaction, request_id, next, signer, now_utc, Vec::new())?;
        transaction.commit()?;
        Ok(cose)
    }

    fn transition_terminal_with_evidence(
        &mut self,
        request_id: &PublicId,
        expected: RequestState,
        next: RequestState,
        signer: &BrokerSigningKey,
        now_utc: i64,
        authorization_evidence: Vec<CborValue>,
    ) -> Result<Vec<u8>, BrokerError> {
        if !next.is_terminal() || !expected.permits(next) {
            return Err(BrokerError::InvalidTransition {
                from: expected,
                to: next,
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_identity(&transaction, signer)?;
        append_transition(
            &transaction,
            request_id,
            Some(expected),
            next,
            transition_reason(next),
        )?;
        let cose = create_receipt(
            &transaction,
            request_id,
            next,
            signer,
            now_utc,
            authorization_evidence,
        )?;
        transaction.commit()?;
        Ok(cose)
    }

    #[cfg(test)]
    fn transition(
        &mut self,
        request_id: &PublicId,
        expected: RequestState,
        next: RequestState,
    ) -> Result<RequestState, BrokerError> {
        if !expected.permits(next) {
            return Err(BrokerError::InvalidTransition {
                from: expected,
                to: next,
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        append_transition(
            &transaction,
            request_id,
            Some(expected),
            next,
            transition_reason(next),
        )?;
        transaction.commit()?;
        Ok(next)
    }

    /// Retrieves one caller-authorized broker-signed receipt. Authorization is
    /// deliberately enforced by the API layer using the stored requester UID.
    pub fn receipt(&self, request_id: &PublicId) -> Result<Option<Vec<u8>>, BrokerError> {
        self.connection
            .query_row(
                "SELECT cose_bytes FROM receipts WHERE request_id = ?1",
                [request_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(BrokerError::from)
    }

    fn deadline_elapsed(
        &self,
        request_id: &PublicId,
        now_mono_ns: u64,
    ) -> Result<bool, BrokerError> {
        let deadline: Option<i64> = self.connection.query_row(
            "SELECT deadline_mono_ns FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| row.get(0),
        )?;
        let deadline = deadline.ok_or(BrokerError::CorruptState)?;
        Ok(now_mono_ns >= u64::try_from(deadline).map_err(|_| BrokerError::NumericOutOfRange)?)
    }

    fn credential_generation(&self) -> Result<u64, BrokerError> {
        let generation: i64 = self.connection.query_row(
            "SELECT credential_generation FROM broker_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)
    }

    fn pinned_credentials(&self, generation: u64) -> Result<Vec<PinnedCredential>, BrokerError> {
        let generation = i64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)?;
        let mut statement = self.connection.prepare(
            "SELECT credential_id, generation, quarantined, cose_algorithm, sign_count
             FROM credentials WHERE generation = ?1",
        )?;
        statement
            .query_map([generation], |row| {
                Ok(PinnedCredential {
                    credential_id: row.get(0)?,
                    generation: u64::try_from(row.get::<_, i64>(1)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    quarantined: row.get::<_, i64>(2)? != 0,
                    cose_algorithm: row.get(3)?,
                    previous_sign_count: u32::try_from(row.get::<_, i64>(4)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(BrokerError::from)
    }

    /// Reads a request summary for an already-authorized local caller.
    pub fn request(&self, request_id: &PublicId) -> Result<Option<RequestSummary>, BrokerError> {
        self.connection
            .query_row(
                "SELECT requester_uid, state, generation FROM requests WHERE request_id = ?1",
                [request_id.as_str()],
                |row| {
                    let uid = row.get::<_, i64>(0)?;
                    let state = row.get::<_, String>(1)?;
                    let generation = row.get::<_, i64>(2)?;
                    summary_from_values(request_id.clone(), uid, &state, generation)
                        .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
                },
            )
            .optional()
            .map_err(BrokerError::from)
    }

    /// Reads the durable event chain for a request. This is intended for the
    /// future receipt/relay signer, not for a requester-facing RPC response.
    pub fn events(&self, request_id: &PublicId) -> Result<Vec<LifecycleEvent>, BrokerError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, state, reason, previous_event_digest, event_digest
             FROM request_events WHERE request_id = ?1 ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([request_id.as_str()], |row| {
            let sequence = row.get::<_, i64>(0)?;
            let state = row.get::<_, String>(1)?;
            let reason = row.get::<_, i64>(2)?;
            let previous = row.get::<_, Option<Vec<u8>>>(3)?;
            let digest = row.get::<_, Vec<u8>>(4)?;
            Ok((sequence, state, reason, previous, digest))
        })?;
        rows.map(|row| {
            let (sequence, state, reason, previous, digest) = row?;
            let previous_event_digest = previous
                .map(|value| value.try_into().map_err(|_| BrokerError::CorruptState))
                .transpose()?;
            let event_digest = digest.try_into().map_err(|_| BrokerError::CorruptState)?;
            Ok(LifecycleEvent {
                sequence: u64::try_from(sequence).map_err(|_| BrokerError::NumericOutOfRange)?,
                previous_event_digest,
                state: RequestState::from_db(&state)?,
                reason: transition_reason_from_code(reason)?,
                event_digest,
            })
        })
        .collect()
    }
}

/// Confirms that the signer has been explicitly pinned to this database before
/// it is permitted to authorize an irreversible broker record.
fn ensure_identity(
    transaction: &Transaction<'_>,
    signer: &BrokerSigningKey,
) -> Result<(), BrokerError> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT key_kid, public_key FROM broker_identity WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match existing {
        Some((kid, public_key))
            if kid == signer.kid && public_key.as_slice() == signer.public_key() =>
        {
            Ok(())
        }
        Some(_) | None => Err(BrokerError::UnsafeKey),
    }
}

struct IdempotencyRecord {
    input_digest: [u8; 32],
    summary: RequestSummary,
}

fn lookup_idempotency(
    transaction: &Transaction<'_>,
    requester_uid: RequesterUid,
    operation_key: &OperationKey,
) -> Result<Option<IdempotencyRecord>, BrokerError> {
    transaction
        .query_row(
            "SELECT request_id, input_digest, state, generation FROM requests WHERE requester_uid = ?1 AND operation_key = ?2",
            params![i64::from(requester_uid.as_u32()), operation_key.as_str()],
            |row| {
                let request_id = row.get::<_, String>(0)?;
                let digest = row.get::<_, Vec<u8>>(1)?;
                let state = row.get::<_, String>(2)?;
                let generation = row.get::<_, i64>(3)?;
                let input_digest: [u8; 32] = digest.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                let request_id = PublicId::parse(request_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
                let summary = summary_from_values(request_id, i64::from(requester_uid.as_u32()), &state, generation)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
                Ok(IdempotencyRecord { input_digest, summary })
            },
        )
        .optional()
        .map_err(BrokerError::from)
}

const COSE_CONTENT_TYPE_REQUEST: u64 = 1;
const COSE_CONTENT_TYPE_RECEIPT: u64 = 3;

fn create_receipt(
    transaction: &Transaction<'_>,
    request_id: &PublicId,
    terminal_state: RequestState,
    signer: &BrokerSigningKey,
    now_utc: i64,
    authorization_evidence: Vec<CborValue>,
) -> Result<Vec<u8>, BrokerError> {
    let receipt_id = PublicId::random()?;
    let (requester_uid, request_digest, plan_digest, created_utc, recovery_evidence): (
        i64,
        Vec<u8>,
        Option<Vec<u8>>,
        i64,
        Option<Vec<u8>>,
    ) = transaction.query_row(
        "SELECT requester_uid, COALESCE(request_digest, input_digest), plan_digest, created_utc, recovery_evidence
             FROM requests WHERE request_id = ?1",
        [request_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    let request_digest: Digest = request_digest
        .try_into()
        .map_err(|_| BrokerError::CorruptState)?;
    let plan_digest = plan_digest
        .map(|value| value.try_into().map_err(|_| BrokerError::CorruptState))
        .transpose()?
        .unwrap_or([0; 32]);
    let broker_epoch: i64 = transaction.query_row(
        "SELECT boot_epoch FROM broker_metadata WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let mut execution_evidence = vec![(
        CborValue::Unsigned(1),
        CborValue::Unsigned(receipt_state_code(terminal_state)),
    )];
    if let Some(evidence) = recovery_evidence {
        let evidence_digest: Digest = Sha256::digest(evidence).into();
        execution_evidence.push((
            CborValue::Unsigned(2),
            CborValue::Bytes(evidence_digest.to_vec()),
        ));
    }
    let receipt = Receipt {
        receipt_id: ReceiptId::new(receipt_id.bytes()?),
        request_id: RequestId::new(request_id.bytes()?),
        request_digest,
        plan_digest,
        terminal_state: receipt_state_code(terminal_state),
        authorization_evidence,
        prestate_evidence: CborValue::Map(Vec::new()),
        execution_evidence: CborValue::Map(execution_evidence),
        created_utc,
        completed_utc: now_utc,
        broker_epoch: u64::try_from(broker_epoch).map_err(|_| BrokerError::NumericOutOfRange)?,
    };
    let payload = receipt
        .canonical_bytes()
        .map_err(|_| BrokerError::Receipt)?;
    let cose = CoseSign1::sign(
        payload,
        signer.kid.clone(),
        COSE_CONTENT_TYPE_RECEIPT,
        Domain::Receipt,
        &signer.key,
    )
    .and_then(|envelope| envelope.encode())
    .map_err(|_| BrokerError::Receipt)?;
    transaction.execute(
        "INSERT INTO receipts (receipt_id, request_id, requester_uid, terminal_state, cose_bytes, created_utc, completed_utc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            receipt_id.as_str(),
            request_id.as_str(),
            requester_uid,
            terminal_state.as_db(),
            cose,
            created_utc,
            now_utc,
        ],
    )?;
    let cose = transaction.query_row(
        "SELECT cose_bytes FROM receipts WHERE request_id = ?1",
        [request_id.as_str()],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    transaction.execute(
        "UPDATE requests SET receipt_bytes = ?1 WHERE request_id = ?2",
        params![cose.as_slice(), request_id.as_str()],
    )?;
    Ok(cose)
}

const fn receipt_state_code(state: RequestState) -> u64 {
    match state {
        RequestState::NoChange => 1,
        RequestState::Invalid => 2,
        RequestState::Denied => 3,
        RequestState::Expired => 4,
        RequestState::Cancelled => 5,
        RequestState::Stale => 6,
        RequestState::Succeeded => 7,
        RequestState::Failed => 8,
        RequestState::RecoveryRequired => 9,
        RequestState::Planning
        | RequestState::Pending
        | RequestState::Approved
        | RequestState::Executing => 0,
    }
}

fn request_state(
    transaction: &Transaction<'_>,
    request_id: &PublicId,
) -> Result<Option<RequestState>, BrokerError> {
    transaction
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map_or(Ok(None), |state| RequestState::from_db(&state).map(Some))
}

/// Appends a transition inside the caller's `BEGIN IMMEDIATE` transaction.
/// `expected=None` is reserved for startup recovery, where a pre-reboot
/// monotonic deadline cannot be compared after the clock reset.  In all other
/// cases the state compare-and-set and event insertion share one commit.
fn append_transition(
    transaction: &Transaction<'_>,
    request_id: &PublicId,
    expected: Option<RequestState>,
    next: RequestState,
    reason: TransitionReason,
) -> Result<(), BrokerError> {
    let changed = match expected {
        Some(expected) => transaction.execute(
            "UPDATE requests SET state = ?1 WHERE request_id = ?2 AND state = ?3",
            params![next.as_db(), request_id.as_str(), expected.as_db()],
        )?,
        None => transaction.execute(
            "UPDATE requests SET state = ?1 WHERE request_id = ?2",
            params![next.as_db(), request_id.as_str()],
        )?,
    };
    if changed != 1 {
        let actual = request_state(transaction, request_id)?;
        return match actual {
            Some(actual) => Err(BrokerError::LifecycleRaceLost { actual }),
            None => Err(BrokerError::NotFound),
        };
    }
    let (sequence, previous_event_digest) = transaction.query_row(
        "SELECT sequence, event_digest FROM request_events WHERE request_id = ?1 ORDER BY sequence DESC LIMIT 1",
        [request_id.as_str()],
        |row| {
            let sequence = row.get::<_, i64>(0)?;
            let digest = row.get::<_, Vec<u8>>(1)?;
            Ok((sequence, digest))
        },
    )?;
    let sequence = u64::try_from(sequence)
        .map_err(|_| BrokerError::NumericOutOfRange)?
        .checked_add(1)
        .ok_or(BrokerError::NumericOutOfRange)?;
    let previous_event_digest: Digest = previous_event_digest
        .try_into()
        .map_err(|_| BrokerError::CorruptState)?;
    let event_digest = lifecycle_event_digest(
        request_id,
        sequence,
        Some(previous_event_digest),
        next,
        reason,
    );
    transaction.execute(
        "INSERT INTO request_events (request_id, sequence, state, reason, previous_event_digest, event_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request_id.as_str(),
            i64::try_from(sequence).map_err(|_| BrokerError::NumericOutOfRange)?,
            next.as_db(),
            reason.code(),
            previous_event_digest.as_slice(),
            event_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn summary_from_values(
    request_id: PublicId,
    requester_uid: i64,
    state: &str,
    generation: i64,
) -> Result<RequestSummary, BrokerError> {
    Ok(RequestSummary {
        request_id,
        requester_uid: RequesterUid(
            u32::try_from(requester_uid).map_err(|_| BrokerError::NumericOutOfRange)?,
        ),
        state: RequestState::from_db(state)?,
        generation: u64::try_from(generation).map_err(|_| BrokerError::NumericOutOfRange)?,
    })
}

fn input_digest(package_name: &PackageName) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"rootpermit/v1/package-install-input\0");
    hasher.update(package_name.as_str().as_bytes());
    hasher.finalize().into()
}

fn random_bytes_16() -> Result<[u8; 16], BrokerError> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

const fn is_package_character(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'.' | b'-')
}

/// Result produced by the planner before a request can be presented for approval.
///
/// The real APT adapter is deliberately not represented here.  It belongs behind
/// the M4 helper boundary.  This type gives M2 a deterministic, testable seam
/// without letting a caller supply a plan, version, archive, or APT option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    /// A frozen transition that is safe to bind into a pending request.
    Pending(FrozenPlan),
    /// The requested package is already in the desired state.
    NoChange { reason_code: u16 },
    /// Planning rejected the typed request without invoking a helper.
    Invalid { reason_code: u16 },
}

/// Minimal immutable projection of a frozen plan available before the APT
/// helper exists.  `manifest_digest` is supplied only by a trusted planner.
/// The complete v1 `PlanManifest` / `FrozenPlan` schema remains a protocol-crate
/// gap and must replace this projection before real execution is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenPlan {
    pub package_name: PackageName,
    pub manifest_digest: Digest,
    pub plan_digest: Digest,
    pub action_count: u32,
}

impl FrozenPlan {
    /// Constructs a deterministic fake-plan projection for M2 tests.
    pub fn fake(
        package_name: PackageName,
        manifest_digest: Digest,
        action_count: u32,
    ) -> Result<Self, PlannerError> {
        let view = CborValue::Map(vec![
            (
                CborValue::Unsigned(1),
                CborValue::Text(package_name.as_str().to_owned()),
            ),
            (
                CborValue::Unsigned(2),
                CborValue::Bytes(manifest_digest.to_vec()),
            ),
            (
                CborValue::Unsigned(3),
                CborValue::Unsigned(u64::from(action_count)),
            ),
        ]);
        let plan_digest =
            digest_cbor(Domain::AptPlan, &view).map_err(|_| PlannerError::Canonicalization)?;
        Ok(Self {
            package_name,
            manifest_digest,
            plan_digest,
            action_count,
        })
    }

    fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (
                CborValue::Unsigned(1),
                CborValue::Text(self.package_name.as_str().to_owned()),
            ),
            (
                CborValue::Unsigned(2),
                CborValue::Bytes(self.manifest_digest.to_vec()),
            ),
            (
                CborValue::Unsigned(3),
                CborValue::Unsigned(u64::from(self.action_count)),
            ),
        ])
    }
}

/// Trusted planner seam. Implementations receive only a validated base package
/// name and cannot recover any discarded agent arguments.
pub trait Planner {
    fn plan(&self, package_name: &PackageName) -> Result<PlanOutcome, PlannerError>;
}

/// Planner failures are deliberately opaque to the requester-facing API.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlannerError {
    #[error("planner could not produce a deterministic canonical plan")]
    Canonicalization,
    #[error("planner is temporarily unavailable")]
    Unavailable,
}

/// Deterministic planner used by M2 lifecycle tests. It cannot execute APT,
/// inspect the host, or manufacture an arbitrary package transition.
#[derive(Debug, Clone, Default)]
pub struct FakePlanner {
    outcomes: BTreeMap<PackageName, PlanOutcome>,
}

impl FakePlanner {
    #[must_use]
    pub fn with_outcomes(outcomes: impl IntoIterator<Item = (PackageName, PlanOutcome)>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
        }
    }
}

impl Planner for FakePlanner {
    fn plan(&self, package_name: &PackageName) -> Result<PlanOutcome, PlannerError> {
        Ok(self
            .outcomes
            .get(package_name)
            .cloned()
            .unwrap_or(PlanOutcome::Invalid { reason_code: 1 }))
    }
}

/// Reason recorded with a local state transition. Values are stable local audit
/// codes, not a replacement for the still-unimplemented v1 protocol event map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    Created,
    PlannerPending,
    PlannerNoChange,
    PlannerInvalid,
    Approved,
    Denied,
    Expired,
    Cancelled,
    GenerationStale,
    ExecutionStarted,
    ExecutionSucceeded,
    ExecutionFailed,
    RecoveryRequired,
    ReconciledSucceeded,
    ReconciledFailed,
}

impl TransitionReason {
    const fn code(self) -> u64 {
        match self {
            Self::Created => 1,
            Self::PlannerPending => 2,
            Self::PlannerNoChange => 3,
            Self::PlannerInvalid => 4,
            Self::Approved => 5,
            Self::Denied => 6,
            Self::Expired => 7,
            Self::Cancelled => 8,
            Self::GenerationStale => 9,
            Self::ExecutionStarted => 10,
            Self::ExecutionSucceeded => 11,
            Self::ExecutionFailed => 12,
            Self::RecoveryRequired => 13,
            Self::ReconciledSucceeded => 14,
            Self::ReconciledFailed => 15,
        }
    }
}

fn transition_reason(state: RequestState) -> TransitionReason {
    match state {
        RequestState::Planning => TransitionReason::Created,
        RequestState::Pending => TransitionReason::PlannerPending,
        RequestState::NoChange => TransitionReason::PlannerNoChange,
        RequestState::Invalid => TransitionReason::PlannerInvalid,
        RequestState::Approved => TransitionReason::Approved,
        RequestState::Denied => TransitionReason::Denied,
        RequestState::Expired => TransitionReason::Expired,
        RequestState::Cancelled => TransitionReason::Cancelled,
        RequestState::Stale => TransitionReason::GenerationStale,
        RequestState::Executing => TransitionReason::ExecutionStarted,
        RequestState::Succeeded => TransitionReason::ExecutionSucceeded,
        RequestState::Failed => TransitionReason::ExecutionFailed,
        RequestState::RecoveryRequired => TransitionReason::RecoveryRequired,
    }
}

fn transition_reason_from_code(value: i64) -> Result<TransitionReason, BrokerError> {
    match value {
        1 => Ok(TransitionReason::Created),
        2 => Ok(TransitionReason::PlannerPending),
        3 => Ok(TransitionReason::PlannerNoChange),
        4 => Ok(TransitionReason::PlannerInvalid),
        5 => Ok(TransitionReason::Approved),
        6 => Ok(TransitionReason::Denied),
        7 => Ok(TransitionReason::Expired),
        8 => Ok(TransitionReason::Cancelled),
        9 => Ok(TransitionReason::GenerationStale),
        10 => Ok(TransitionReason::ExecutionStarted),
        11 => Ok(TransitionReason::ExecutionSucceeded),
        12 => Ok(TransitionReason::ExecutionFailed),
        13 => Ok(TransitionReason::RecoveryRequired),
        14 => Ok(TransitionReason::ReconciledSucceeded),
        15 => Ok(TransitionReason::ReconciledFailed),
        _ => Err(BrokerError::CorruptState),
    }
}

/// Append-only local lifecycle event with a deterministic hash-chain link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub sequence: u64,
    pub previous_event_digest: Option<Digest>,
    pub state: RequestState,
    pub reason: TransitionReason,
    pub event_digest: Digest,
}

/// Unsigned receipt content prepared by M2. A broker signature cannot be added
/// yet because `rp-protocol` has no public COSE or Receipt schema interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptDraft {
    pub receipt_id: PublicId,
    pub request_id: PublicId,
    pub request_digest: Digest,
    pub plan_digest: Option<Digest>,
    pub terminal_state: RequestState,
    pub final_event_digest: Digest,
    pub receipt_digest: Digest,
}

/// A verifier is the only route by which an assertion reaches M2. The WebAuthn
/// parser/verifier is intentionally outside this crate; an unverified decision
/// must never be represented by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDecision {
    pub request_digest: Digest,
    pub generation: u64,
    pub decision: Decision,
    pub assertion_digest: Digest,
}

/// Deterministic lifecycle authority used by the broker transaction layer.
/// Calls are intentionally serialized by `BrokerStore`'s `BEGIN IMMEDIATE`
/// transaction in a production adapter; this value object makes every race
/// winner and event-chain result independently testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRecord {
    pub request_id: PublicId,
    pub receipt_id: PublicId,
    pub requested_package: PackageName,
    pub request_digest: Digest,
    pub generation: u64,
    pub deadline_mono_ns: u64,
    pub state: RequestState,
    pub plan: Option<FrozenPlan>,
    pub events: Vec<LifecycleEvent>,
    pub receipt: Option<ReceiptDraft>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    #[error("lifecycle action is not allowed from {state:?}")]
    InvalidState { state: RequestState },
    #[error("verified decision does not bind this request")]
    DecisionContextMismatch,
    #[error("verified decision was made for stale credential generation")]
    DecisionGenerationStale,
    #[error("a terminal state already won the lifecycle race")]
    AlreadyTerminal,
    #[error("receipt is available only after a terminal state")]
    ReceiptNotReady,
    #[error("planner result does not bind the requested package")]
    PlannerPackageMismatch,
}

impl LifecycleRecord {
    /// Creates the durable in-memory representation immediately after typed
    /// input was accepted. Both IDs are broker-generated opaque identifiers.
    #[must_use]
    pub fn new(
        request_id: PublicId,
        receipt_id: PublicId,
        requested_package: PackageName,
        request_digest: Digest,
        generation: u64,
        deadline_mono_ns: u64,
    ) -> Self {
        let mut record = Self {
            request_id,
            receipt_id,
            requested_package,
            request_digest,
            generation,
            deadline_mono_ns,
            state: RequestState::Planning,
            plan: None,
            events: Vec::new(),
            receipt: None,
        };
        record.append(RequestState::Planning, TransitionReason::Created);
        record
    }

    /// Applies a trusted planner output. No decision or execution can happen
    /// while the record remains in `planning`.
    pub fn apply_plan(&mut self, outcome: PlanOutcome) -> Result<RequestState, LifecycleError> {
        if self.state != RequestState::Planning {
            return Err(self.state_error());
        }
        match outcome {
            PlanOutcome::Pending(plan) => {
                if plan.package_name != self.requested_package {
                    return Err(LifecycleError::PlannerPackageMismatch);
                }
                self.plan = Some(plan);
                self.winner(RequestState::Pending, TransitionReason::PlannerPending);
            }
            PlanOutcome::NoChange { .. } => {
                self.winner(RequestState::NoChange, TransitionReason::PlannerNoChange);
            }
            PlanOutcome::Invalid { .. } => {
                self.winner(RequestState::Invalid, TransitionReason::PlannerInvalid);
            }
        }
        Ok(self.state)
    }

    /// Accepts exactly one already-verified, context-bound decision. Expiry and
    /// generation changes are checked before the decision so their durable
    /// terminal transition wins deterministically.
    pub fn apply_verified_decision(
        &mut self,
        now_mono_ns: u64,
        active_generation: u64,
        decision: &VerifiedDecision,
    ) -> Result<RequestState, LifecycleError> {
        self.pre_execution_guard(now_mono_ns, active_generation)?;
        if self.state != RequestState::Pending {
            return Err(self.state_error());
        }
        if decision.request_digest != self.request_digest {
            return Err(LifecycleError::DecisionContextMismatch);
        }
        if decision.generation != self.generation {
            return Err(LifecycleError::DecisionGenerationStale);
        }
        match decision.decision {
            Decision::Approve => self.winner(RequestState::Approved, TransitionReason::Approved),
            Decision::Deny => self.winner(RequestState::Denied, TransitionReason::Denied),
        }
        Ok(self.state)
    }

    /// Cancels only before execution. A cancelled request cannot later be
    /// approved or handed to the helper.
    pub fn cancel(
        &mut self,
        now_mono_ns: u64,
        active_generation: u64,
    ) -> Result<RequestState, LifecycleError> {
        self.pre_execution_guard(now_mono_ns, active_generation)?;
        if !matches!(self.state, RequestState::Pending | RequestState::Approved) {
            return Err(self.state_error());
        }
        self.winner(RequestState::Cancelled, TransitionReason::Cancelled);
        Ok(self.state)
    }

    /// The sole authorization-to-execution transition. A generation change or
    /// expiry always wins before this can reach the helper boundary.
    pub fn begin_execution(
        &mut self,
        now_mono_ns: u64,
        active_generation: u64,
    ) -> Result<RequestState, LifecycleError> {
        self.pre_execution_guard(now_mono_ns, active_generation)?;
        if self.state != RequestState::Approved {
            return Err(self.state_error());
        }
        self.winner(RequestState::Executing, TransitionReason::ExecutionStarted);
        Ok(self.state)
    }

    /// Records a helper-proved outcome. It intentionally has no retry path.
    pub fn finish_execution(
        &mut self,
        succeeded: bool,
        recovery_required: bool,
    ) -> Result<RequestState, LifecycleError> {
        if self.state != RequestState::Executing {
            return Err(self.state_error());
        }
        match (succeeded, recovery_required) {
            (true, false) => self.winner(
                RequestState::Succeeded,
                TransitionReason::ExecutionSucceeded,
            ),
            (false, false) => self.winner(RequestState::Failed, TransitionReason::ExecutionFailed),
            (false, true) => self.winner(
                RequestState::RecoveryRequired,
                TransitionReason::RecoveryRequired,
            ),
            (true, true) => return Err(LifecycleError::InvalidState { state: self.state }),
        }
        Ok(self.state)
    }

    /// Root-only reconciliation has to prove either result; this method models
    /// only the state-machine edge and deliberately cannot restart execution.
    pub fn reconcile(&mut self, succeeded: bool) -> Result<RequestState, LifecycleError> {
        if self.state != RequestState::RecoveryRequired {
            return Err(self.state_error());
        }
        if succeeded {
            self.winner(
                RequestState::Succeeded,
                TransitionReason::ReconciledSucceeded,
            );
        } else {
            self.winner(RequestState::Failed, TransitionReason::ReconciledFailed);
        }
        Ok(self.state)
    }

    fn pre_execution_guard(
        &mut self,
        now_mono_ns: u64,
        active_generation: u64,
    ) -> Result<(), LifecycleError> {
        if self.state.is_terminal() {
            return Err(LifecycleError::AlreadyTerminal);
        }
        if matches!(self.state, RequestState::Pending | RequestState::Approved)
            && now_mono_ns >= self.deadline_mono_ns
        {
            self.winner(RequestState::Expired, TransitionReason::Expired);
            return Err(LifecycleError::AlreadyTerminal);
        }
        if matches!(self.state, RequestState::Pending | RequestState::Approved)
            && active_generation != self.generation
        {
            self.winner(RequestState::Stale, TransitionReason::GenerationStale);
            return Err(LifecycleError::AlreadyTerminal);
        }
        Ok(())
    }

    fn state_error(&self) -> LifecycleError {
        if self.state.is_terminal() {
            LifecycleError::AlreadyTerminal
        } else {
            LifecycleError::InvalidState { state: self.state }
        }
    }

    fn winner(&mut self, next: RequestState, reason: TransitionReason) {
        debug_assert!(self.state.permits(next));
        self.state = next;
        self.append(next, reason);
        if next.is_terminal() {
            self.receipt = Some(self.make_receipt());
        }
    }

    fn append(&mut self, state: RequestState, reason: TransitionReason) {
        let sequence = u64::try_from(self.events.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let previous_event_digest = self.events.last().map(|event| event.event_digest);
        let event_digest = lifecycle_event_digest(
            &self.request_id,
            sequence,
            previous_event_digest,
            state,
            reason,
        );
        self.events.push(LifecycleEvent {
            sequence,
            previous_event_digest,
            state,
            reason,
            event_digest,
        });
    }

    fn make_receipt(&self) -> ReceiptDraft {
        let final_event_digest = self
            .events
            .last()
            .map_or([0; 32], |event| event.event_digest);
        let plan_digest = self
            .plan
            .as_ref()
            .and_then(|plan| (plan.plan_digest != [0; 32]).then_some(plan.plan_digest));
        let receipt_digest = receipt_digest(
            &self.receipt_id,
            &self.request_id,
            self.request_digest,
            plan_digest,
            self.state,
            final_event_digest,
        );
        ReceiptDraft {
            receipt_id: self.receipt_id.clone(),
            request_id: self.request_id.clone(),
            request_digest: self.request_digest,
            plan_digest,
            terminal_state: self.state,
            final_event_digest,
            receipt_digest,
        }
    }
}

fn lifecycle_event_digest(
    request_id: &PublicId,
    sequence: u64,
    previous_event_digest: Option<Digest>,
    state: RequestState,
    reason: TransitionReason,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rootpermit/v1/local-lifecycle-event\0");
    hasher.update(request_id.as_str().as_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_event_digest.unwrap_or([0; 32]));
    hasher.update(state.as_db().as_bytes());
    hasher.update(reason.code().to_be_bytes());
    hasher.finalize().into()
}

fn receipt_digest(
    receipt_id: &PublicId,
    request_id: &PublicId,
    request_digest: Digest,
    plan_digest: Option<Digest>,
    state: RequestState,
    final_event_digest: Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"rootpermit/v1/local-receipt-draft\0");
    hasher.update(receipt_id.as_str().as_bytes());
    hasher.update(request_id.as_str().as_bytes());
    hasher.update(request_digest);
    hasher.update(plan_digest.unwrap_or([0; 32]));
    hasher.update(state.as_db().as_bytes());
    hasher.update(final_event_digest);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rp_web_authn::LibraryVerifiedAssertion;

    const REQUEST_A: &str = "AbCdEfGhIjKlMnOpQrStUw";
    const REQUEST_B: &str = "ZyXwVuTsRqPoNmLkJiHgFe";
    const KEY_A: &str = "aBcDeFgHiJkLmNoPqRsTuVwX";
    const KEY_B: &str = "zYxWvUtSrQpOnMlKjIhGfEdC";

    fn request(id: &str, uid: u32, key: &str, package: &str) -> SubmitPackageInstall {
        SubmitPackageInstall {
            request_id: PublicId::parse(id).unwrap(),
            requester_uid: RequesterUid::from_peer_cred(uid),
            operation_key: OperationKey::parse(key).unwrap(),
            package_name: PackageName::parse(package).unwrap(),
            generation: 3,
        }
    }

    fn allow(package: &str) -> PackageAllowlist {
        PackageAllowlist::new([PackageName::parse(package).unwrap()])
    }

    fn test_signer() -> BrokerSigningKey {
        BrokerSigningKey::from_seed([7; 32])
    }

    fn pending_context() -> PendingRequestContext {
        PendingRequestContext {
            created_utc: 10,
            expires_utc: 20,
            boot_id: [1; 16],
            deadline_mono_ns: 100,
            nonce: [2; 32],
            policy_id: [3; 16],
            policy_digest: [4; 32],
        }
    }

    fn relying_party() -> WebAuthnRelyingParty {
        WebAuthnRelyingParty {
            rp_id: "rootpermit.example".into(),
            origin: "https://rootpermit.example".into(),
        }
    }

    struct FakeWebAuthnVerifier;

    impl ReviewedWebAuthnVerifier for FakeWebAuthnVerifier {
        fn verify_assertion(
            &self,
            submission: &DecisionSubmission,
            _credential: &PinnedCredential,
        ) -> Result<LibraryVerifiedAssertion, ()> {
            Ok(LibraryVerifiedAssertion {
                credential_id: submission.credential_id.clone(),
                client_data_type: "webauthn.get".into(),
                challenge: submission
                    .approval_context
                    .webauthn_challenge()
                    .map_err(|_| ())?
                    .to_vec(),
                origin: submission.approval_context.origin.clone(),
                rp_id_hash: Sha256::digest(submission.approval_context.rp_id.as_bytes()).into(),
                user_present: true,
                user_verified: true,
                cose_algorithm: rp_web_authn::ES256_ALGORITHM,
                sign_count: 1,
            })
        }
    }

    #[test]
    fn package_intake_rejects_versions_urls_paths_flags_and_architectures() {
        for invalid in [
            "f",
            "ffmpeg=7",
            "ffmpeg:amd64",
            "https://example.test/pkg",
            "./ffmpeg",
            "--assume-yes",
            "ffmpeg;id",
            "FFmpeg",
            "ff mpeg",
            "ffmpeg/../apt",
            "ffmpeg_1",
        ] {
            assert_eq!(
                PackageName::parse(invalid),
                Err(IntakeError::InvalidPackageName),
                "{invalid}"
            );
        }
        assert_eq!(PackageName::parse("ffmpeg").unwrap().as_str(), "ffmpeg");
        assert_eq!(PackageName::parse("libvpx7").unwrap().as_str(), "libvpx7");
    }

    #[test]
    fn policy_denial_creates_no_request() {
        let mut store = BrokerStore::in_memory().unwrap();
        let denied = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        let error = store.submit(denied.clone(), &allow("curl")).unwrap_err();
        assert!(matches!(error, BrokerError::PolicyDenied));
        assert_eq!(store.request(&denied.request_id).unwrap(), None);
    }

    #[test]
    fn exact_uid_key_retry_recovers_original_but_changed_input_conflicts() {
        let mut store = BrokerStore::in_memory().unwrap();
        let policy = PackageAllowlist::new([
            PackageName::parse("ffmpeg").unwrap(),
            PackageName::parse("curl").unwrap(),
        ]);
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        assert!(matches!(
            store.submit(initial.clone(), &policy).unwrap(),
            SubmitOutcome::Created(_)
        ));

        let retry = request(REQUEST_B, 1000, KEY_A, "ffmpeg");
        assert_eq!(
            store.submit(retry, &policy).unwrap(),
            SubmitOutcome::Existing(RequestSummary {
                request_id: initial.request_id.clone(),
                requester_uid: initial.requester_uid,
                state: RequestState::Planning,
                generation: initial.generation,
            })
        );
        let changed = request(REQUEST_B, 1000, KEY_A, "curl");
        assert!(matches!(
            store.submit(changed, &policy),
            Err(BrokerError::IdempotencyConflict)
        ));
    }

    #[test]
    fn active_slot_is_global_per_broker_and_releases_only_at_terminal_state() {
        let mut store = BrokerStore::in_memory().unwrap();
        let policy = PackageAllowlist::new([
            PackageName::parse("ffmpeg").unwrap(),
            PackageName::parse("curl").unwrap(),
        ]);
        let first = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        let second = request(REQUEST_B, 1001, KEY_B, "curl");
        store.submit(first.clone(), &policy).unwrap();
        assert!(matches!(
            store.submit(second.clone(), &policy),
            Err(BrokerError::Busy { .. })
        ));
        store
            .transition(
                &first.request_id,
                RequestState::Planning,
                RequestState::NoChange,
            )
            .unwrap();
        assert!(matches!(
            store.submit(second, &policy).unwrap(),
            SubmitOutcome::Created(_)
        ));
    }

    #[test]
    fn recovery_required_retains_the_active_slot_until_root_reconciliation() {
        let mut store = BrokerStore::in_memory().unwrap();
        let policy = PackageAllowlist::new([
            PackageName::parse("ffmpeg").unwrap(),
            PackageName::parse("curl").unwrap(),
        ]);
        let first = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        let second = request(REQUEST_B, 1001, KEY_B, "curl");
        store.submit(first.clone(), &policy).unwrap();
        store
            .transition(
                &first.request_id,
                RequestState::Planning,
                RequestState::Pending,
            )
            .unwrap();
        store
            .transition(
                &first.request_id,
                RequestState::Pending,
                RequestState::Approved,
            )
            .unwrap();
        store
            .transition(
                &first.request_id,
                RequestState::Approved,
                RequestState::Executing,
            )
            .unwrap();
        store
            .transition(
                &first.request_id,
                RequestState::Executing,
                RequestState::RecoveryRequired,
            )
            .unwrap();
        assert!(matches!(
            store.submit(second.clone(), &policy),
            Err(BrokerError::Busy { .. })
        ));
        store
            .transition(
                &first.request_id,
                RequestState::RecoveryRequired,
                RequestState::Failed,
            )
            .unwrap();
        assert!(matches!(
            store.submit(second, &policy),
            Ok(SubmitOutcome::Created(_))
        ));
    }

    #[test]
    fn terminal_transition_writes_exactly_one_signed_durable_receipt() {
        let signer = test_signer();
        let mut store = BrokerStore::in_memory().unwrap();
        store.initialize_identity(&signer).unwrap();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Planning,
                RequestState::Pending,
            )
            .unwrap();
        let receipt = store
            .transition_terminal(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Denied,
                &signer,
                1,
            )
            .unwrap();
        assert_eq!(store.receipt(&initial.request_id).unwrap(), Some(receipt));
        assert!(matches!(
            store.transition_terminal(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Denied,
                &signer,
                2,
            ),
            Err(BrokerError::LifecycleRaceLost {
                actual: RequestState::Denied
            })
        ));
    }

    #[test]
    fn recovery_reconciliation_requires_evidence_and_cannot_restart_execution() {
        let signer = test_signer();
        let mut store = BrokerStore::in_memory().unwrap();
        store.initialize_identity(&signer).unwrap();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Planning,
                RequestState::Pending,
            )
            .unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Approved,
            )
            .unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Approved,
                RequestState::Executing,
            )
            .unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Executing,
                RequestState::RecoveryRequired,
            )
            .unwrap();
        assert!(matches!(
            store.reconcile_recovery(&initial.request_id, false, &[], &signer, 1),
            Err(BrokerError::CorruptState)
        ));
        assert!(
            store
                .reconcile_recovery(
                    &initial.request_id,
                    false,
                    b"verified final state",
                    &signer,
                    2
                )
                .is_ok()
        );
        assert_eq!(
            store.request(&initial.request_id).unwrap().unwrap().state,
            RequestState::Failed
        );
        assert!(matches!(
            store.transition_nonterminal(
                &initial.request_id,
                RequestState::Failed,
                RequestState::Executing,
            ),
            Err(BrokerError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn signed_request_and_webauthn_deny_bind_one_durable_terminal_receipt() {
        let signer = test_signer();
        let mut store = BrokerStore::in_memory().unwrap();
        store.initialize_identity(&signer).unwrap();
        store
            .replace_credentials(
                3,
                &[CredentialPin {
                    credential_id: vec![9],
                    public_key_cose: vec![1],
                    cose_algorithm: rp_web_authn::ES256_ALGORITHM,
                }],
            )
            .unwrap();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
        let plan = pending_plan();
        let request_cose = store
            .prepare_for_decision(&initial.request_id, &plan, &pending_context(), &signer)
            .unwrap();
        let signed = CoseSign1::decode(&request_cose).unwrap();
        assert_eq!(signed.content_type, COSE_CONTENT_TYPE_REQUEST);
        let signed_request = Request::decode(&signed.payload).unwrap();
        assert_eq!(
            signed_request.request_id,
            RequestId::new(initial.request_id.bytes().unwrap())
        );
        assert_eq!(signed_request.nonce, Nonce::new([2; 32]));
        assert_eq!(signed_request.plan_digest, plan.plan_digest);

        let context = store
            .approval_context(&initial.request_id, Decision::Deny, &relying_party())
            .unwrap();
        let submission = DecisionSubmission {
            approval_context: context,
            credential_id: vec![9],
            authenticator_data: vec![1],
            client_data_json: vec![2],
            signature: vec![3],
            user_handle: None,
        };
        let outcome = store
            .apply_webauthn_submission(
                &initial.request_id,
                &submission,
                &FakeWebAuthnVerifier,
                &relying_party(),
                &signer,
                50,
                15,
            )
            .unwrap();
        assert_eq!(outcome.state, RequestState::Denied);
        let receipt_cose = outcome.receipt_cose.unwrap();
        let receipt = Receipt::decode(&CoseSign1::decode(&receipt_cose).unwrap().payload).unwrap();
        assert_eq!(receipt.request_digest, signed_request.digest().unwrap());
        assert_eq!(
            store.receipt(&initial.request_id).unwrap(),
            Some(receipt_cose)
        );
    }

    #[test]
    fn lifecycle_cas_and_terminal_edges_fail_closed() {
        let mut store = BrokerStore::in_memory().unwrap();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
        assert!(matches!(
            store.transition(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Approved
            ),
            Err(BrokerError::LifecycleRaceLost {
                actual: RequestState::Planning
            })
        ));
        assert!(matches!(
            store.transition(
                &initial.request_id,
                RequestState::Planning,
                RequestState::Executing
            ),
            Err(BrokerError::InvalidTransition { .. })
        ));
        store
            .transition(
                &initial.request_id,
                RequestState::Planning,
                RequestState::Pending,
            )
            .unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Denied,
            )
            .unwrap();
        assert!(RequestState::Denied.is_terminal());
        assert!(!RequestState::Denied.permits(RequestState::Approved));
        assert!(matches!(
            store.transition(
                &initial.request_id,
                RequestState::Denied,
                RequestState::Approved
            ),
            Err(BrokerError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn sqlite_transition_persists_a_contiguous_hash_chain_in_the_same_transaction() {
        let mut store = BrokerStore::in_memory().unwrap();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Planning,
                RequestState::Pending,
            )
            .unwrap();
        store
            .transition(
                &initial.request_id,
                RequestState::Pending,
                RequestState::Denied,
            )
            .unwrap();
        let events = store.events(&initial.request_id).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].previous_event_digest, None);
        assert_eq!(
            events[1].previous_event_digest,
            Some(events[0].event_digest)
        );
        assert_eq!(
            events[2].previous_event_digest,
            Some(events[1].event_digest)
        );
        assert_eq!(events[2].reason, TransitionReason::Denied);
    }

    #[test]
    #[ignore = "requires a root-owned durable broker file"]
    fn durable_open_migrates_and_reboot_expires_non_executing_work() {
        let path = std::env::temp_dir().join(format!(
            "rootpermit-m2-{}-{}.sqlite",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let signer = test_signer();
        let initial = request(REQUEST_A, 1000, KEY_A, "ffmpeg");
        {
            let mut store = BrokerStore::open(&path).unwrap();
            store.initialize_identity(&signer).unwrap();
            store.submit(initial.clone(), &allow("ffmpeg")).unwrap();
            assert_eq!(store.start_boot(7, &signer, 1).unwrap(), 1);
            assert_eq!(
                store.request(&initial.request_id).unwrap().unwrap().state,
                RequestState::Expired
            );
            assert_eq!(store.start_boot(7, &signer, 2).unwrap(), 0);
            assert!(store.receipt(&initial.request_id).unwrap().is_some());
        }
        let reopened = BrokerStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .request(&initial.request_id)
                .unwrap()
                .unwrap()
                .state,
            RequestState::Expired
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn all_documented_lifecycle_edges_are_accepted_and_undocumented_edges_rejected() {
        let accepted = [
            (RequestState::Planning, RequestState::Pending),
            (RequestState::Planning, RequestState::NoChange),
            (RequestState::Planning, RequestState::Invalid),
            (RequestState::Pending, RequestState::Approved),
            (RequestState::Pending, RequestState::Denied),
            (RequestState::Pending, RequestState::Expired),
            (RequestState::Pending, RequestState::Cancelled),
            (RequestState::Pending, RequestState::Stale),
            (RequestState::Approved, RequestState::Executing),
            (RequestState::Approved, RequestState::Cancelled),
            (RequestState::Approved, RequestState::Stale),
            (RequestState::Approved, RequestState::Expired),
            (RequestState::Executing, RequestState::Succeeded),
            (RequestState::Executing, RequestState::Failed),
            (RequestState::Executing, RequestState::RecoveryRequired),
            (RequestState::RecoveryRequired, RequestState::Succeeded),
            (RequestState::RecoveryRequired, RequestState::Failed),
        ];
        assert!(accepted.into_iter().all(|(from, to)| from.permits(to)));
        assert!(!RequestState::Planning.permits(RequestState::Succeeded));
        assert!(!RequestState::Approved.permits(RequestState::Denied));
        assert!(!RequestState::Succeeded.permits(RequestState::Failed));
    }

    fn lifecycle() -> LifecycleRecord {
        LifecycleRecord::new(
            PublicId::parse(REQUEST_A).unwrap(),
            PublicId::parse(REQUEST_B).unwrap(),
            PackageName::parse("ffmpeg").unwrap(),
            [9; 32],
            3,
            100,
        )
    }

    fn pending_plan() -> FrozenPlan {
        FrozenPlan::fake(PackageName::parse("ffmpeg").unwrap(), [7; 32], 2).unwrap()
    }

    #[test]
    fn fake_planner_is_deterministic_and_cannot_change_the_requested_package() {
        let plan = pending_plan();
        let planner = FakePlanner::with_outcomes([(
            PackageName::parse("ffmpeg").unwrap(),
            PlanOutcome::Pending(plan.clone()),
        )]);
        assert_eq!(
            planner
                .plan(&PackageName::parse("ffmpeg").unwrap())
                .unwrap(),
            PlanOutcome::Pending(plan)
        );
        assert_eq!(
            planner.plan(&PackageName::parse("curl").unwrap()).unwrap(),
            PlanOutcome::Invalid { reason_code: 1 }
        );

        let mut record = lifecycle();
        let changed = FrozenPlan::fake(PackageName::parse("curl").unwrap(), [7; 32], 1).unwrap();
        assert_eq!(
            record.apply_plan(PlanOutcome::Pending(changed)),
            Err(LifecycleError::PlannerPackageMismatch)
        );
        assert_eq!(record.state, RequestState::Planning);
    }

    #[test]
    fn decision_expiry_cancel_and_generation_have_one_durable_winner() {
        let mut approved = lifecycle();
        approved
            .apply_plan(PlanOutcome::Pending(pending_plan()))
            .unwrap();
        let proof = VerifiedDecision {
            request_digest: [9; 32],
            generation: 3,
            decision: Decision::Approve,
            assertion_digest: [4; 32],
        };
        assert_eq!(
            approved.apply_verified_decision(99, 3, &proof).unwrap(),
            RequestState::Approved
        );
        assert_eq!(
            approved.begin_execution(99, 4),
            Err(LifecycleError::AlreadyTerminal)
        );
        assert_eq!(approved.state, RequestState::Stale);
        assert_eq!(approved.cancel(99, 3), Err(LifecycleError::AlreadyTerminal));

        let mut expired = lifecycle();
        expired
            .apply_plan(PlanOutcome::Pending(pending_plan()))
            .unwrap();
        assert_eq!(expired.cancel(100, 3), Err(LifecycleError::AlreadyTerminal));
        assert_eq!(expired.state, RequestState::Expired);

        let mut denied = lifecycle();
        denied
            .apply_plan(PlanOutcome::Pending(pending_plan()))
            .unwrap();
        let deny = VerifiedDecision {
            request_digest: [9; 32],
            generation: 3,
            decision: Decision::Deny,
            assertion_digest: [5; 32],
        };
        assert_eq!(
            denied.apply_verified_decision(99, 3, &deny).unwrap(),
            RequestState::Denied
        );
        assert_eq!(
            denied.apply_verified_decision(99, 3, &proof),
            Err(LifecycleError::AlreadyTerminal)
        );
    }

    #[test]
    fn terminal_receipt_draft_commits_to_the_event_chain_without_claiming_a_signature() {
        let mut record = lifecycle();
        record
            .apply_plan(PlanOutcome::Pending(pending_plan()))
            .unwrap();
        let proof = VerifiedDecision {
            request_digest: [9; 32],
            generation: 3,
            decision: Decision::Approve,
            assertion_digest: [4; 32],
        };
        record.apply_verified_decision(99, 3, &proof).unwrap();
        record.begin_execution(99, 3).unwrap();
        record.finish_execution(false, true).unwrap();
        assert_eq!(record.receipt, None);
        record.reconcile(false).unwrap();
        let receipt = record.receipt.clone().unwrap();
        assert_eq!(receipt.terminal_state, RequestState::Failed);
        assert_eq!(receipt.plan_digest, Some(pending_plan().plan_digest));
        assert_eq!(
            receipt.final_event_digest,
            record.events.last().unwrap().event_digest
        );
        assert!(
            record
                .events
                .windows(2)
                .all(|events| events[1].previous_event_digest == Some(events[0].event_digest))
        );
        assert_ne!(receipt.receipt_digest, [0; 32]);
    }
}
