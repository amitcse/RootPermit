//! Durable M4 execution markers.
//!
//! A journal is evidence, not a retry queue.  It is deliberately append-only,
//! flushed before each externally visible phase, and treats a truncated record,
//! helper crash, or missing final proof as `recovery_required`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;

const MAGIC: [u8; 8] = *b"RPJNLv1\0";
const RECORD_BYTES: usize = 10;

/// Durable points surrounding all privileged side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum JournalMarker {
    HelperHandoff = 1,
    SimulationProved = 2,
    ExecutionStarted = 3,
    ArchivesAccepted = 4,
    UnpackStarted = 5,
    ConfigureStarted = 6,
    TriggersStarted = 7,
    ResultSucceeded = 8,
    ResultFailed = 9,
    ReceiptCreated = 10,
    FinalStateCommitted = 11,
}

impl JournalMarker {
    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::HelperHandoff),
            2 => Some(Self::SimulationProved),
            3 => Some(Self::ExecutionStarted),
            4 => Some(Self::ArchivesAccepted),
            5 => Some(Self::UnpackStarted),
            6 => Some(Self::ConfigureStarted),
            7 => Some(Self::TriggersStarted),
            8 => Some(Self::ResultSucceeded),
            9 => Some(Self::ResultFailed),
            10 => Some(Self::ReceiptCreated),
            11 => Some(Self::FinalStateCommitted),
            _ => None,
        }
    }
}

/// The only restart outcomes permitted before root records reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    Succeeded,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("execution journal is corrupt or truncated")]
    Corrupt,
    #[error("execution journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Root-owned append-only journal.  No API rewrites an existing sequence.
pub struct ExecutionJournal {
    file: File,
    next_sequence: u64,
}

impl ExecutionJournal {
    /// Opens a new or existing journal and rejects a malformed prefix before
    /// any M4 helper may be started.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let next_sequence = if contents.is_empty() {
            file.write_all(&MAGIC)?;
            file.sync_all()?;
            1
        } else {
            parse_records(&contents)?
        };
        Ok(Self {
            file,
            next_sequence,
        })
    }

    /// Appends and synchronizes one marker before the associated operation.
    pub fn append(&mut self, marker: JournalMarker) -> Result<u64, JournalError> {
        let sequence = self.next_sequence;
        let mut record = [0_u8; RECORD_BYTES];
        record[..8].copy_from_slice(&sequence.to_be_bytes());
        record[8] = marker as u8;
        record[9] = checksum(sequence, marker as u8);
        self.file.write_all(&record)?;
        self.file.sync_data()?;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(sequence)
    }

    /// Re-reads a durable journal and returns only a result that its own marker
    /// order proves.  Ambiguous executions never auto-retry.
    pub fn classify(path: &Path) -> Result<RecoveryClassification, JournalError> {
        let contents = std::fs::read(path)?;
        let next = parse_records(&contents)?;
        if next == 1 {
            return Ok(RecoveryClassification::RecoveryRequired);
        }
        let markers = records(&contents)?;
        let final_state = markers.last().copied() == Some(JournalMarker::FinalStateCommitted);
        let Some(result_index) = markers.iter().position(|marker| {
            matches!(
                marker,
                JournalMarker::ResultSucceeded | JournalMarker::ResultFailed
            )
        }) else {
            return Ok(RecoveryClassification::RecoveryRequired);
        };
        let expected_prefix = [
            JournalMarker::HelperHandoff,
            JournalMarker::SimulationProved,
            JournalMarker::ExecutionStarted,
        ];
        let receipt_after_result = markers
            .iter()
            .skip(result_index + 1)
            .any(|marker| *marker == JournalMarker::ReceiptCreated);
        if !final_state || !markers.starts_with(&expected_prefix) || !receipt_after_result {
            return Ok(RecoveryClassification::RecoveryRequired);
        }
        let succeeded = markers
            .iter()
            .filter(|marker| **marker == JournalMarker::ResultSucceeded)
            .count();
        let failed = markers
            .iter()
            .filter(|marker| **marker == JournalMarker::ResultFailed)
            .count();
        match (succeeded, failed) {
            (1, 0) => Ok(RecoveryClassification::Succeeded),
            (0, 1) => Ok(RecoveryClassification::Failed),
            _ => Ok(RecoveryClassification::RecoveryRequired),
        }
    }
}

fn parse_records(contents: &[u8]) -> Result<u64, JournalError> {
    if contents.len() < MAGIC.len() || contents[..MAGIC.len()] != MAGIC {
        return Err(JournalError::Corrupt);
    }
    let remainder = &contents[MAGIC.len()..];
    if remainder.len() % RECORD_BYTES != 0 {
        return Err(JournalError::Corrupt);
    }
    let mut expected = 1_u64;
    for record in remainder.chunks_exact(RECORD_BYTES) {
        let sequence =
            u64::from_be_bytes(record[..8].try_into().map_err(|_| JournalError::Corrupt)?);
        let marker = JournalMarker::from_byte(record[8]).ok_or(JournalError::Corrupt)?;
        if sequence != expected || record[9] != checksum(sequence, marker as u8) {
            return Err(JournalError::Corrupt);
        }
        expected = expected.saturating_add(1);
    }
    Ok(expected)
}

fn records(contents: &[u8]) -> Result<Vec<JournalMarker>, JournalError> {
    parse_records(contents)?;
    contents[MAGIC.len()..]
        .chunks_exact(RECORD_BYTES)
        .map(|record| JournalMarker::from_byte(record[8]).ok_or(JournalError::Corrupt))
        .collect()
}

const fn checksum(sequence: u64, marker: u8) -> u8 {
    let bytes = sequence.to_be_bytes();
    bytes[0] ^ bytes[2] ^ bytes[4] ^ bytes[6] ^ marker ^ 0xa7
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("rootpermit-m4-journal-{suffix}"))
    }

    #[test]
    fn only_a_single_proven_result_with_receipt_and_final_commit_is_terminal() {
        let path = path();
        let mut journal = ExecutionJournal::open(&path).unwrap();
        journal.append(JournalMarker::HelperHandoff).unwrap();
        journal.append(JournalMarker::SimulationProved).unwrap();
        journal.append(JournalMarker::ExecutionStarted).unwrap();
        assert_eq!(
            ExecutionJournal::classify(&path).unwrap(),
            RecoveryClassification::RecoveryRequired
        );
        journal.append(JournalMarker::ResultSucceeded).unwrap();
        journal.append(JournalMarker::ReceiptCreated).unwrap();
        journal.append(JournalMarker::FinalStateCommitted).unwrap();
        assert_eq!(
            ExecutionJournal::classify(&path).unwrap(),
            RecoveryClassification::Succeeded
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_torn_or_conflicting_journal_never_claims_success() {
        let path = path();
        let mut journal = ExecutionJournal::open(&path).unwrap();
        journal.append(JournalMarker::ExecutionStarted).unwrap();
        drop(journal);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(1);
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            ExecutionJournal::classify(&path),
            Err(JournalError::Corrupt)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn terminal_markers_without_a_proven_execution_are_not_success() {
        let path = path();
        let mut journal = ExecutionJournal::open(&path).unwrap();
        journal.append(JournalMarker::ResultSucceeded).unwrap();
        journal.append(JournalMarker::ReceiptCreated).unwrap();
        journal.append(JournalMarker::FinalStateCommitted).unwrap();
        assert_eq!(
            ExecutionJournal::classify(&path).unwrap(),
            RecoveryClassification::RecoveryRequired
        );
        std::fs::remove_file(path).unwrap();
    }
}
