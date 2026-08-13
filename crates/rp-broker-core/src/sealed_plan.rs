//! Descriptor-relative sealed APT plan storage.
//!
//! The broker writes immutable bytes into a content-addressed store, then
//! creates a read-only plan directory which contains only the deterministic
//! manifest.  The helper is handed already-open directory descriptors; it is
//! never given a requester-controlled path.  Linux does not expose `openat2`
//! through the Rust standard library, so every child is addressed through a
//! held directory descriptor (`/proc/self/fd/<n>/…`) with `O_NOFOLLOW` and a
//! closed, digest-only name vocabulary.  This preserves the important
//! no-symlink/beneath-root property without an unsafe syscall wrapper.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

const O_NOFOLLOW: i32 = 0o400_000;
const O_DIRECTORY: i32 = 0o200_000;
const MAX_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const MANIFEST_NAME: &str = "manifest.cbor";

/// Opaque broker-generated plan reference.  It is deliberately an identifier,
/// not a filesystem path accepted from an RPC caller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanHandle(String);

impl PlanHandle {
    /// Parses exactly the public 128-bit base64url representation used by the
    /// broker's opaque identifiers.
    pub fn parse(value: impl Into<String>) -> Result<Self, SealedPlanError> {
        let value = value.into();
        if value.len() != 22
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || URL_SAFE_NO_PAD
                .decode(&value)
                .ok()
                .is_none_or(|bytes| bytes.len() != 16)
        {
            return Err(SealedPlanError::InvalidPlanHandle);
        }
        Ok(Self(value))
    }

    /// Returns the opaque identifier for broker-owned audit records only.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bytes captured by a trusted planner.  Roles are recorded in the canonical
/// manifest; the store intentionally sees only immutable object bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedObject {
    pub bytes: Vec<u8>,
}

/// The descriptors transferred to the helper at fixed ABI slots.  They keep
/// the validated inodes alive through process creation and prevent a later
/// pathname substitution from changing what the helper sees.
#[derive(Debug)]
pub struct SealedPlanHandoff {
    pub handle: PlanHandle,
    pub plan_root: File,
    pub content_store: File,
}

impl SealedPlanHandoff {
    /// File descriptor to inherit as the helper plan root (ABI fd 4).
    #[must_use]
    pub fn plan_root_fd(&self) -> i32 {
        self.plan_root.as_raw_fd()
    }

    /// File descriptor to inherit as the helper content store (ABI fd 6).
    #[must_use]
    pub fn content_store_fd(&self) -> i32 {
        self.content_store.as_raw_fd()
    }
}

/// Fail-closed errors for the sealed-plan boundary.  Callers must map every
/// variant to a pre-execution planning failure, never to a live APT fallback.
#[derive(Debug, Error)]
pub enum SealedPlanError {
    #[error("sealed-plan root is unsafe")]
    UnsafeRoot,
    #[error("sealed-plan path component is invalid")]
    InvalidPlanHandle,
    #[error("sealed object is too large")]
    ObjectTooLarge,
    #[error("sealed object digest does not match its bytes")]
    DigestMismatch,
    #[error("sealed object already exists with different bytes")]
    ObjectCollision,
    #[error("sealed plan already exists")]
    PlanAlreadyExists,
    #[error("sealed plan does not exist")]
    PlanMissing,
    #[error("sealed-plan filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Root-owned sealed-plan store rooted at `/var/lib/rootpermit` in production.
/// Opening it verifies the root and every held directory before any child is
/// created or read.
#[derive(Debug)]
pub struct SealedPlanStore {
    root: File,
    objects: File,
    plans: File,
    expected_uid: u32,
}

impl SealedPlanStore {
    /// Opens the root-owned store.  Production callers require UID 0 and
    /// private modes before creating any content or plan directory.
    pub fn open(root: &Path) -> Result<Self, SealedPlanError> {
        Self::open_for_uid(root, 0)
    }

    fn open_for_uid(root: &Path, expected_uid: u32) -> Result<Self, SealedPlanError> {
        let root = open_directory(root)?;
        validate_directory(&root, expected_uid, 0o077)?;
        ensure_directory(&root, "sha256", expected_uid)?;
        ensure_directory(&root, "plans", expected_uid)?;
        let objects = open_child_directory(&root, "sha256")?;
        let plans = open_child_directory(&root, "plans")?;
        validate_directory(&objects, expected_uid, 0o077)?;
        validate_directory(&plans, expected_uid, 0o077)?;
        Ok(Self {
            root,
            objects,
            plans,
            expected_uid,
        })
    }

    /// Stores an immutable object under its SHA-256 name and returns that
    /// lowercase digest.  Existing objects are re-read and checked, so a
    /// content-address collision or post-write replacement fails closed.
    pub fn put_object(&self, object: &SealedObject) -> Result<String, SealedPlanError> {
        if u64::try_from(object.bytes.len()).map_or(true, |size| size > MAX_OBJECT_BYTES) {
            return Err(SealedPlanError::ObjectTooLarge);
        }
        let digest = hex_digest(&object.bytes);
        match open_child_file(&self.objects, &digest, false) {
            Ok(mut existing) => {
                verify_immutable_file(&existing, self.expected_uid, &digest)?;
                let mut bytes = Vec::new();
                existing.read_to_end(&mut bytes)?;
                if bytes != object.bytes {
                    return Err(SealedPlanError::ObjectCollision);
                }
                return Ok(digest);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(O_NOFOLLOW)
            .open(child_path(&self.objects, &digest))?;
        file.write_all(&object.bytes)?;
        file.sync_all()?;
        fs::set_permissions(
            child_path(&self.objects, &digest),
            fs::Permissions::from_mode(0o400),
        )?;
        drop(file);
        let file = open_child_file(&self.objects, &digest, false)?;
        verify_immutable_file(&file, self.expected_uid, &digest)?;
        Ok(digest)
    }

    /// Creates a plan directory after every referenced input has already been
    /// stored and revalidated.  `manifest` is intentionally opaque here: the
    /// helper's canonical-CBOR parser validates it again before APT starts.
    pub fn seal_plan(
        &self,
        handle: PlanHandle,
        manifest: &[u8],
        referenced_digests: &[String],
    ) -> Result<SealedPlanHandoff, SealedPlanError> {
        if u64::try_from(manifest.len()).map_or(true, |size| size > MAX_OBJECT_BYTES) {
            return Err(SealedPlanError::ObjectTooLarge);
        }
        for digest in referenced_digests {
            if !is_digest_name(digest) {
                return Err(SealedPlanError::DigestMismatch);
            }
            let object = open_child_file(&self.objects, digest, false)?;
            verify_immutable_file(&object, self.expected_uid, digest)?;
        }

        let plan_path = child_path(&self.plans, handle.as_str());
        match fs::create_dir(&plan_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(SealedPlanError::PlanAlreadyExists);
            }
            Err(error) => return Err(error.into()),
        }
        let plan = open_child_directory(&self.plans, handle.as_str())?;
        validate_directory(&plan, self.expected_uid, 0o077)?;
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(O_NOFOLLOW)
            .open(child_path(&plan, MANIFEST_NAME))?;
        manifest_file.write_all(manifest)?;
        manifest_file.sync_all()?;
        fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o500))?;
        fs::set_permissions(
            child_path(&plan, MANIFEST_NAME),
            fs::Permissions::from_mode(0o400),
        )?;
        drop(manifest_file);
        let manifest_file = open_child_file(&plan, MANIFEST_NAME, false)?;
        validate_manifest_file(&manifest_file, self.expected_uid)?;
        Ok(SealedPlanHandoff {
            handle,
            plan_root: plan,
            content_store: self.objects.try_clone()?,
        })
    }

    /// Reopens a previously sealed plan by descriptor-relative opaque handle.
    /// It is used only for a root-controlled recovery inspection.
    pub fn handoff(&self, handle: PlanHandle) -> Result<SealedPlanHandoff, SealedPlanError> {
        let plan = open_child_directory(&self.plans, handle.as_str()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SealedPlanError::PlanMissing
            } else {
                SealedPlanError::Io(error)
            }
        })?;
        validate_directory(&plan, self.expected_uid, 0o077)?;
        let manifest = open_child_file(&plan, MANIFEST_NAME, false)?;
        validate_manifest_file(&manifest, self.expected_uid)?;
        Ok(SealedPlanHandoff {
            handle,
            plan_root: plan,
            content_store: self.objects.try_clone()?,
        })
    }

    /// Keeps the root descriptor live for the lifetime of the store.  This is
    /// intentionally observable only in tests and diagnostics.
    #[must_use]
    pub fn root_fd(&self) -> i32 {
        self.root.as_raw_fd()
    }
}

fn open_directory(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)
}

fn open_child_directory(parent: &File, name: &str) -> Result<File, std::io::Error> {
    if !is_safe_component(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe directory component",
        ));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(child_path(parent, name))
}

fn open_child_file(parent: &File, name: &str, write: bool) -> Result<File, std::io::Error> {
    if !is_safe_component(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe file component",
        ));
    }
    OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(O_NOFOLLOW)
        .open(child_path(parent, name))
}

fn ensure_directory(parent: &File, name: &str, expected_uid: u32) -> Result<(), SealedPlanError> {
    let path = child_path(parent, name);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let directory = open_child_directory(parent, name)?;
    validate_directory(&directory, expected_uid, 0o077)
}

fn child_path(parent: &File, component: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        parent.as_raw_fd(),
        component
    ))
}

fn validate_directory(
    file: &File,
    expected_uid: u32,
    forbidden_mode: u32,
) -> Result<(), SealedPlanError> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & forbidden_mode != 0
    {
        return Err(SealedPlanError::UnsafeRoot);
    }
    Ok(())
}

fn validate_manifest_file(file: &File, expected_uid: u32) -> Result<(), SealedPlanError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o222 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_OBJECT_BYTES
    {
        return Err(SealedPlanError::UnsafeRoot);
    }
    Ok(())
}

fn verify_immutable_file(
    file: &File,
    expected_uid: u32,
    expected_digest: &str,
) -> Result<(), SealedPlanError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o222 != 0
        || metadata.nlink() != 1
        || metadata.len() > MAX_OBJECT_BYTES
    {
        return Err(SealedPlanError::UnsafeRoot);
    }
    let mut reader = file.try_clone()?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if hex_digest(&bytes) != expected_digest {
        return Err(SealedPlanError::DigestMismatch);
    }
    Ok(())
}

fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value != "."
        && value != ".."
}

fn is_digest_name(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte <= b'f'))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rootpermit-sealed-plan-{nonce}"));
        fs::create_dir(&path).expect("temporary root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private root");
        path
    }

    fn store(root: &Path) -> SealedPlanStore {
        // Metadata supplies the owner of our freshly-created private directory
        // without widening the production root-only constructor.
        let uid = fs::metadata(root).expect("test root metadata").uid();
        SealedPlanStore::open_for_uid(root, uid).expect("test store")
    }

    #[test]
    fn seals_content_by_digest_and_reopens_only_an_opaque_plan_handle() {
        let root = temporary_root();
        let store = store(&root);
        let digest = store
            .put_object(&SealedObject {
                bytes: b"sealed archive".to_vec(),
            })
            .unwrap();
        let handle = PlanHandle::parse("AQEBAQEBAQEBAQEBAQEBAQ").unwrap();
        let handoff = store
            .seal_plan(handle.clone(), b"canonical manifest", &[digest])
            .unwrap();
        assert!(handoff.plan_root_fd() >= 0);
        assert!(handoff.content_store_fd() >= 0);
        drop(handoff);
        assert_eq!(
            store.handoff(handle).unwrap().handle.as_str(),
            "AQEBAQEBAQEBAQEBAQEBAQ"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_hardlinks_post_seal_mutation_and_path_traversal() {
        let root = temporary_root();
        let store = store(&root);
        let digest = store
            .put_object(&SealedObject {
                bytes: b"a".to_vec(),
            })
            .unwrap();
        let object_path = root.join("sha256").join(&digest);
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            store.seal_plan(
                PlanHandle::parse("AgICAgICAgICAgICAgICAg").unwrap(),
                b"m",
                std::slice::from_ref(&digest)
            ),
            Err(SealedPlanError::UnsafeRoot)
        ));
        fs::set_permissions(&object_path, fs::Permissions::from_mode(0o400)).unwrap();
        fs::hard_link(&object_path, root.join("copy")).unwrap();
        assert!(matches!(
            store.seal_plan(
                PlanHandle::parse("AwMDAwMDAwMDAwMDAwMDAw").unwrap(),
                b"m",
                &[digest]
            ),
            Err(SealedPlanError::UnsafeRoot)
        ));
        assert!(PlanHandle::parse("../../not-a-plan").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
