//! Sentinel's core: an append-only log and the authenticated tree over it.
//!
//! Layering, innermost first. Each layer depends only on the ones above it in
//! this list, which is what lets the tree be thrown away and rebuilt:
//!
//! | module     | owns                                                      |
//! |------------|-----------------------------------------------------------|
//! | `sha256`   | the hash, implemented here rather than imported            |
//! | `crc32c`   | storage framing integrity, nothing cryptographic           |
//! | `hash`     | RFC 6962 domain separation and the left-complete split     |
//! | `record`   | the canonical bytes that get hashed, and the storage frame |
//! | `tree`     | derived Merkle state, rebuildable from the log             |
//! | `proof`    | inclusion and consistency, generation and verification     |
//! | `log`      | the persisted source of truth, and recovery                |
//! | `ffi`      | the C ABI the Go service links against                     |
//!
//! No external crates. `Cargo.toml` has no `[dependencies]` section at all,
//! and that is the point rather than an accident: a transparency log whose
//! hash function, tree, and proofs are all someone else's code has not
//! implemented a transparency log. The one place this costs something is
//! SHA-256 performance, and `bench/` reports the gap honestly.

pub mod crc32c;
pub mod ffi;
pub mod hash;
pub mod log;
pub mod proof;
pub mod record;
pub mod sha256;
pub mod tree;

pub use hash::{from_hex, hash_children, hash_empty, hash_leaf, to_hex, Hash, HASH_LEN};
pub use log::{Log, LogError, Recovery, SyncPolicy};
pub use proof::{verify_consistency, verify_inclusion, ProofError};
pub use record::{DecodeError, Entry};
pub use tree::MerkleTree;
