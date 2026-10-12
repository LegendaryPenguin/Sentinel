//! The append-only log, and the recovery that makes it trustworthy.
//!
//! This is the source of truth. The tree in `tree.rs` is derived state: it is
//! rebuilt from these bytes on every open and never persisted. I built it in
//! that order deliberately — if both were persisted, a disagreement between
//! them would have no arbiter, and "which one is right" is not a question a
//! transparency log gets to be unsure about.
//!
//! The recovery rule that matters is the distinction between two failures
//! that look superficially alike:
//!
//!   * A **torn tail** — the process died between `write` and `fsync`, so the
//!     final record is incomplete. The entry was never acknowledged to any
//!     client and no root was ever published containing it, so discarding it
//!     loses nothing. Recoverable.
//!
//!   * A **corrupt record** — a complete, framed record whose CRC does not
//!     match. Those bytes were acknowledged and are now something other than
//!     what was written. Skipping it to "keep the log usable" would silently
//!     renumber every later entry and change every root: that is precisely
//!     the history rewrite this whole project exists to detect. Fatal, and
//!     reported with the position so an operator can go and look.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::{hash_leaf, Hash};
use crate::proof::ProofError;
use crate::record::{DecodeError, Entry};
use crate::tree::MerkleTree;

/// When to force bytes to the platter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    /// fsync before `append` returns. The only setting under which an
    /// acknowledged entry is actually durable, and the default for that
    /// reason.
    EveryAppend,
    /// Leave it to the OS. Available because the benchmarks need to separate
    /// the cost of hashing from the cost of durability, and because tests
    /// that append thousands of entries should not take minutes. Not a
    /// production setting, and `append` says so by still returning normally —
    /// there is no way to signal "probably durable".
    Never,
}

#[derive(Debug)]
pub enum LogError {
    Io(std::io::Error),
    /// A complete record that fails its integrity check. Unrecoverable by
    /// design; see the module comment.
    Corrupt {
        position: u64,
        offset: u64,
        source: DecodeError,
    },
    /// A record's stored position does not follow its predecessor. Means the
    /// file has been spliced, not merely damaged.
    PositionGap {
        expected: u64,
        found: u64,
        offset: u64,
    },
    Proof(ProofError),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::Io(e) => write!(f, "io: {e}"),
            LogError::Corrupt {
                position,
                offset,
                source,
            } => write!(
                f,
                "entry {position} at byte {offset} is corrupt: {source} \
                 (the log is not safe to serve; it has been modified after the fact)"
            ),
            LogError::PositionGap {
                expected,
                found,
                offset,
            } => write!(
                f,
                "entry at byte {offset} claims position {found}, expected {expected}: \
                 the log has been spliced"
            ),
            LogError::Proof(e) => write!(f, "proof: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<std::io::Error> for LogError {
    fn from(e: std::io::Error) -> Self {
        LogError::Io(e)
    }
}

impl From<ProofError> for LogError {
    fn from(e: ProofError) -> Self {
        LogError::Proof(e)
    }
}

/// What `open` found and did, so a caller can report it rather than having
/// recovery be invisible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recovery {
    pub entries_loaded: u64,
    /// Bytes discarded from an incomplete trailing record. Non-zero means the
    /// previous process died mid-append.
    pub tail_bytes_discarded: u64,
}

pub struct Log {
    file: File,
    path: PathBuf,
    tree: MerkleTree,
    /// Byte offset of each record. Entries are read back from disk on demand
    /// rather than held in memory: the tree needs 32 bytes per entry and
    /// cannot avoid it, but the payloads can stay on disk, and a transparency
    /// log's payloads are the part that grows without bound.
    offsets: Vec<u64>,
    end: u64,
    sync: SyncPolicy,
}

impl Log {
    /// Opens or creates the log at `path`, replaying it to rebuild the tree.
    pub fn open(path: impl AsRef<Path>, sync: SyncPolicy) -> Result<(Log, Recovery), LogError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        let mut tree = MerkleTree::new();
        let mut offsets = Vec::new();
        let mut off = 0usize;
        let mut recovery = Recovery::default();

        loop {
            if off == bytes.len() {
                break;
            }
            match Entry::decode_storage(&bytes[off..]) {
                Ok((entry, used)) => {
                    let expected = offsets.len() as u64;
                    if entry.position != expected {
                        return Err(LogError::PositionGap {
                            expected,
                            found: entry.position,
                            offset: off as u64,
                        });
                    }
                    tree.push(hash_leaf(&entry.canonical()));
                    offsets.push(off as u64);
                    off += used;
                }
                Err(DecodeError::Truncated) => {
                    // Necessarily the tail: `Truncated` is only returned when
                    // the buffer runs out, and the buffer is the whole file.
                    recovery.tail_bytes_discarded = (bytes.len() - off) as u64;
                    file.set_len(off as u64)?;
                    file.sync_all()?;
                    break;
                }
                Err(source) => {
                    return Err(LogError::Corrupt {
                        position: offsets.len() as u64,
                        offset: off as u64,
                        source,
                    });
                }
            }
        }

        recovery.entries_loaded = offsets.len() as u64;
        file.seek(SeekFrom::Start(off as u64))?;

        Ok((
            Log {
                file,
                path,
                tree,
                offsets,
                end: off as u64,
                sync,
            },
            recovery,
        ))
    }

    pub fn len(&self) -> u64 {
        self.offsets.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `payload` and returns the entry, including the position and
    /// timestamp the log assigned.
    ///
    /// Both are assigned here rather than accepted from the caller. A client
    /// that could choose its own position could overwrite an existing entry;
    /// one that could choose its own timestamp could backdate a record the
    /// log is attesting to having seen.
    pub fn append(&mut self, payload: &[u8]) -> Result<Entry, LogError> {
        let entry = Entry {
            position: self.len(),
            timestamp_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            payload: payload.to_vec(),
        };
        self.append_entry(entry)
    }

    /// Appends a fully formed entry. Exposed for tests and for the recovery
    /// benchmark, which needs timestamps it controls so that roots are
    /// reproducible across runs.
    pub fn append_entry(&mut self, entry: Entry) -> Result<Entry, LogError> {
        assert_eq!(
            entry.position,
            self.len(),
            "append_entry at the wrong position"
        );

        let bytes = entry.encode_storage();
        self.file.seek(SeekFrom::Start(self.end))?;
        self.file.write_all(&bytes)?;
        if self.sync == SyncPolicy::EveryAppend {
            self.file.sync_data()?;
        }

        // The in-memory state is updated only after the bytes are down. If
        // the write fails the tree must not contain a leaf for an entry that
        // is not in the file, or the published root would commit to data the
        // log cannot produce.
        self.tree.push(hash_leaf(&entry.canonical()));
        self.offsets.push(self.end);
        self.end += bytes.len() as u64;

        Ok(entry)
    }

    pub fn entry(&self, position: u64) -> Result<Option<Entry>, LogError> {
        let Some(&offset) = self.offsets.get(position as usize) else {
            return Ok(None);
        };
        let end = self
            .offsets
            .get(position as usize + 1)
            .copied()
            .unwrap_or(self.end);
        let mut buf = vec![0u8; (end - offset) as usize];
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut buf)?;
        match Entry::decode_storage(&buf) {
            Ok((e, _)) => Ok(Some(e)),
            Err(source) => Err(LogError::Corrupt {
                position,
                offset,
                source,
            }),
        }
    }

    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    pub fn root(&self) -> Hash {
        self.tree.root()
    }

    pub fn root_at(&self, size: u64) -> Option<Hash> {
        (size <= self.len()).then(|| self.tree.root_at(size))
    }

    /// Re-reads the file from byte zero, rebuilds the tree, and checks the
    /// result against the live one.
    ///
    /// This is the log auditing itself, which is a weaker thing than the Go
    /// verifier auditing it — same code, same assumptions, so a systematic
    /// error cancels out. It catches the failure it is aimed at, which is
    /// in-memory tree state drifting from the bytes on disk.
    pub fn verify_integrity(&self) -> Result<u64, LogError> {
        let (replayed, _) = Log::open(&self.path, SyncPolicy::Never)?;
        if replayed.len() != self.len() {
            return Err(LogError::PositionGap {
                expected: self.len(),
                found: replayed.len(),
                offset: 0,
            });
        }
        if replayed.root() != self.root() {
            return Err(LogError::Corrupt {
                position: self.len(),
                offset: 0,
                source: DecodeError::BadChecksum { want: 0, got: 0 },
            });
        }
        Ok(replayed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{verify_consistency, verify_inclusion};

    struct Temp(PathBuf);

    impl Temp {
        fn new(tag: &str) -> Temp {
            let mut p = std::env::temp_dir();
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            p.push(format!("sentinel-{tag}-{unique}.log"));
            Temp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn open(t: &Temp) -> (Log, Recovery) {
        Log::open(t.path(), SyncPolicy::Never).unwrap()
    }

    #[test]
    fn empty_log_has_the_empty_root() {
        let t = Temp::new("empty");
        let (log, rec) = open(&t);
        assert_eq!(log.len(), 0);
        assert_eq!(log.root(), crate::hash::hash_empty());
        assert_eq!(rec, Recovery::default());
    }

    #[test]
    fn append_assigns_sequential_positions() {
        let t = Temp::new("positions");
        let (mut log, _) = open(&t);
        for i in 0..50u64 {
            let e = log.append(format!("payload-{i}").as_bytes()).unwrap();
            assert_eq!(e.position, i);
        }
        assert_eq!(log.len(), 50);
    }

    #[test]
    fn entries_read_back_byte_for_byte() {
        let t = Temp::new("readback");
        let (mut log, _) = open(&t);
        let mut written = Vec::new();
        for i in 0..40u64 {
            // Include an empty payload and one with awkward bytes.
            let payload = match i {
                0 => Vec::new(),
                1 => vec![0x00, 0xff, 0x0a, 0x0d],
                _ => format!("payload-{i}").into_bytes(),
            };
            written.push(log.append(&payload).unwrap());
        }
        for e in &written {
            assert_eq!(log.entry(e.position).unwrap().as_ref(), Some(e));
        }
        assert_eq!(log.entry(40).unwrap(), None);
    }

    #[test]
    fn reopen_reconstructs_the_same_root() {
        let t = Temp::new("reopen");
        let expected;
        {
            let (mut log, _) = open(&t);
            for i in 0..73u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
            }
            expected = log.root();
        }
        let (log, rec) = open(&t);
        assert_eq!(rec.entries_loaded, 73);
        assert_eq!(rec.tail_bytes_discarded, 0);
        assert_eq!(log.root(), expected);
    }

    #[test]
    fn reopen_preserves_every_historical_root() {
        // Recovery that reproduces only the final root is not enough: proofs
        // already issued against earlier roots must still verify.
        let t = Temp::new("historical");
        let mut roots = Vec::new();
        {
            let (mut log, _) = open(&t);
            roots.push(log.root());
            for i in 0..60u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
                roots.push(log.root());
            }
        }
        let (log, _) = open(&t);
        for (size, root) in roots.iter().enumerate() {
            assert_eq!(log.root_at(size as u64), Some(*root), "size {size}");
        }
    }

    #[test]
    fn appending_after_reopen_continues_the_same_tree() {
        let t = Temp::new("continue");
        {
            let (mut log, _) = open(&t);
            for i in 0..20u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
            }
        }
        let mid_root;
        {
            let (mut log, _) = open(&t);
            mid_root = log.root();
            for i in 20..45u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
            }
            // The reopened log must still prove consistency with the root it
            // recovered, which only holds if recovery rebuilt the tree
            // identically rather than merely plausibly.
            let proof = log.tree().consistency_proof(20, 45).unwrap();
            verify_consistency(20, 45, &mid_root, &log.root(), &proof).unwrap();
        }
        let (log, rec) = open(&t);
        assert_eq!(rec.entries_loaded, 45);
        assert_eq!(log.root_at(20), Some(mid_root));
    }

    #[test]
    fn torn_tail_is_discarded_and_reported() {
        // Simulate dying mid-write at every possible point inside the last
        // record. All of them must recover to 9 entries, because the tenth
        // was never completed.
        let full = {
            let t = Temp::new("torn-full");
            let (mut log, _) = open(&t);
            for i in 0..10u64 {
                log.append_entry(Entry {
                    position: i,
                    timestamp_nanos: 1_700_000_000_000_000_000 + i,
                    payload: format!("entry-{i}").into_bytes(),
                })
                .unwrap();
            }
            std::fs::read(t.path()).unwrap()
        };
        let nine_root = {
            let t = Temp::new("torn-nine");
            let (mut log, _) = open(&t);
            for i in 0..9u64 {
                log.append_entry(Entry {
                    position: i,
                    timestamp_nanos: 1_700_000_000_000_000_000 + i,
                    payload: format!("entry-{i}").into_bytes(),
                })
                .unwrap();
            }
            log.root()
        };
        let last_record_len = {
            let t = Temp::new("torn-measure");
            let (mut log, _) = open(&t);
            for i in 0..9u64 {
                log.append_entry(Entry {
                    position: i,
                    timestamp_nanos: 1_700_000_000_000_000_000 + i,
                    payload: format!("entry-{i}").into_bytes(),
                })
                .unwrap();
            }
            full.len() - std::fs::metadata(t.path()).unwrap().len() as usize
        };

        for cut in 1..last_record_len {
            let t = Temp::new("torn");
            let truncated = &full[..full.len() - cut];
            std::fs::write(t.path(), truncated).unwrap();

            let (log, rec) = open(&t);
            assert_eq!(log.len(), 9, "cut {cut} of {last_record_len}");
            assert_eq!(rec.entries_loaded, 9);
            assert_eq!(rec.tail_bytes_discarded, (last_record_len - cut) as u64);
            assert_eq!(log.root(), nine_root, "cut {cut}");

            // And the file is actually shortened, so the next append lands in
            // the right place rather than after the garbage.
            let mut log = log;
            log.append(b"after recovery").unwrap();
            assert_eq!(log.len(), 10);
            let reopened = Log::open(t.path(), SyncPolicy::Never).unwrap().0;
            assert_eq!(reopened.root(), log.root());
        }
    }

    #[test]
    fn mid_file_corruption_is_fatal_not_skipped() {
        let t = Temp::new("corrupt");
        {
            let (mut log, _) = open(&t);
            for i in 0..12u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
            }
        }
        let good = std::fs::read(t.path()).unwrap();

        // Corrupt a byte inside the payload of an early record. The framing
        // still parses, so this is the dangerous case: without a CRC the log
        // would come up looking healthy and serving a different history.
        let mut bad = good.clone();
        let target = good.len() / 3;
        bad[target] ^= 0x40;
        std::fs::write(t.path(), &bad).unwrap();

        match Log::open(t.path(), SyncPolicy::Never) {
            Err(LogError::Corrupt { .. }) => {}
            Err(other) => panic!("wrong error for mid-file corruption: {other}"),
            Ok((log, _)) => panic!("corrupt log opened with {} entries", log.len()),
        }
    }

    #[test]
    fn a_spliced_log_is_rejected() {
        // Remove a record from the middle. Every remaining record is
        // individually valid; only the position sequence gives it away.
        let t = Temp::new("splice");
        let mut records = Vec::new();
        for i in 0..6u64 {
            records.push(
                Entry {
                    position: i,
                    timestamp_nanos: 1_700_000_000_000_000_000 + i,
                    payload: format!("entry-{i}").into_bytes(),
                }
                .encode_storage(),
            );
        }
        let mut spliced = Vec::new();
        for (i, r) in records.iter().enumerate() {
            if i == 3 {
                continue;
            }
            spliced.extend_from_slice(r);
        }
        std::fs::write(t.path(), &spliced).unwrap();

        match Log::open(t.path(), SyncPolicy::Never) {
            Err(LogError::PositionGap {
                expected: 3,
                found: 4,
                ..
            }) => {}
            Err(other) => panic!("wrong error for a spliced log: {other}"),
            Ok((log, _)) => panic!("spliced log opened with {} entries", log.len()),
        }
    }

    #[test]
    fn proofs_from_a_recovered_log_still_verify() {
        let t = Temp::new("proofs-after-recovery");
        {
            let (mut log, _) = open(&t);
            for i in 0..64u64 {
                log.append(format!("entry-{i}").as_bytes()).unwrap();
            }
        }
        let (log, _) = open(&t);
        let root = log.root();
        for position in 0..64u64 {
            let entry = log.entry(position).unwrap().unwrap();
            let proof = log.tree().inclusion_proof(position, 64).unwrap();
            verify_inclusion(position, 64, &hash_leaf(&entry.canonical()), &proof, &root)
                .unwrap_or_else(|e| panic!("position {position}: {e}"));
        }
    }

    #[test]
    fn integrity_check_passes_on_a_healthy_log() {
        let t = Temp::new("integrity");
        let (mut log, _) = open(&t);
        for i in 0..30u64 {
            log.append(format!("entry-{i}").as_bytes()).unwrap();
        }
        assert_eq!(log.verify_integrity().unwrap(), 30);
    }

    #[test]
    fn fsync_policy_still_produces_a_readable_log() {
        // The durable path is the default and must not be only exercised
        // implicitly; 200 fsyncs is a tolerable test cost.
        let t = Temp::new("fsync");
        let (mut log, _) = Log::open(t.path(), SyncPolicy::EveryAppend).unwrap();
        for i in 0..200u64 {
            log.append(format!("durable-{i}").as_bytes()).unwrap();
        }
        let root = log.root();
        drop(log);
        let (reopened, rec) = Log::open(t.path(), SyncPolicy::EveryAppend).unwrap();
        assert_eq!(rec.entries_loaded, 200);
        assert_eq!(reopened.root(), root);
    }

    #[test]
    fn empty_payloads_are_real_entries() {
        let t = Temp::new("empty-payload");
        let (mut log, _) = open(&t);
        log.append(b"").unwrap();
        log.append(b"").unwrap();
        assert_eq!(log.len(), 2);
        // Two empty payloads at different positions are different leaves,
        // because position is hashed.
        assert_ne!(
            hash_leaf(&log.entry(0).unwrap().unwrap().canonical()),
            hash_leaf(&log.entry(1).unwrap().unwrap().canonical())
        );
    }
}
