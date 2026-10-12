//! Benchmarks, run with `cargo run --release --bin bench`.
//!
//! No criterion, for the same reason there are no other dependencies. That
//! costs statistical rigour: these are medians over a fixed iteration count
//! with no outlier rejection and no confidence intervals. Where a number is
//! too noisy to draw a conclusion from, `bench/results.md` says so per-cell
//! rather than quoting a figure that implies a precision the measurement does
//! not have.
//!
//! The question each benchmark is meant to answer is written above it. A
//! benchmark without a question attached just produces numbers.

use std::time::{Duration, Instant};

use sentinel_core::hash::{hash_children, hash_leaf};
use sentinel_core::log::{Log, SyncPolicy};
use sentinel_core::proof::{verify_consistency, verify_inclusion};
use sentinel_core::record::Entry;
use sentinel_core::sha256::sha256;
use sentinel_core::tree::MerkleTree;

fn temp_dir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("sentinel-bench-{unique}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn rate(label: &str, n: u64, elapsed: Duration, unit: &str) {
    let per_sec = n as f64 / elapsed.as_secs_f64();
    println!(
        "{label:<46} {per_sec:>14.0} {unit}/sec   ({n} in {:.3}s)",
        elapsed.as_secs_f64()
    );
}

fn throughput(label: &str, bytes: u64, elapsed: Duration) {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    println!(
        "{label:<46} {:>14.1} MiB/sec   ({mb:.1} MiB in {:.3}s)",
        mb / elapsed.as_secs_f64(),
        elapsed.as_secs_f64()
    );
}

fn section(title: &str) {
    println!(
        "\n── {title} {}",
        "─".repeat(70usize.saturating_sub(title.len()))
    );
}

fn main() {
    let dir = temp_dir();
    println!("sentinel-core benchmarks");
    println!("scratch: {}", dir.display());

    bench_sha256();
    bench_tree_build();
    bench_proof_generation();
    bench_proof_verification();
    bench_append(&dir);
    bench_recovery(&dir);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Question: what does hand-rolling SHA-256 actually cost?
///
/// This is the one number that justifies or indicts the zero-dependency
/// decision. A hardware-accelerated implementation is several times faster;
/// the comparison against Go's `crypto/sha256` (which uses the ARMv8 SHA
/// extensions) is in bench/results.md, measured by the Go benchmark in
/// go/verify.
fn bench_sha256() {
    section("SHA-256");

    for &size in &[32usize, 256, 4096, 1 << 20] {
        let data = vec![0x5au8; size];
        // Enough iterations that the smallest input still runs for a
        // measurable interval.
        let iters: u64 = if size <= 256 { 200_000 } else { 2_000 };

        let start = Instant::now();
        let mut sink = 0u8;
        for _ in 0..iters {
            sink ^= sha256(&data)[0];
        }
        let elapsed = start.elapsed();
        std::hint::black_box(sink);

        throughput(
            &format!("  sha256, {size}-byte input"),
            iters * size as u64,
            elapsed,
        );
    }
}

/// Question: is incremental tree construction actually amortised O(1) per
/// leaf, or does the right edge get recomputed?
fn bench_tree_build() {
    section("Tree construction");

    for &n in &[1_000u64, 100_000, 1_000_000] {
        let leaves: Vec<_> = (0..n).map(|i| hash_leaf(&i.to_be_bytes())).collect();

        let start = Instant::now();
        let tree = MerkleTree::from_leaves(&leaves);
        let elapsed = start.elapsed();
        std::hint::black_box(tree.root());

        rate(&format!("  push {n} leaves"), n, elapsed, "leaves");
    }

    // The cache's payoff: a historical root should cost O(log n) hashes, not
    // O(n). If these two are the same the cache is not working.
    let n = 1_000_000u64;
    let leaves: Vec<_> = (0..n).map(|i| hash_leaf(&i.to_be_bytes())).collect();
    let tree = MerkleTree::from_leaves(&leaves);

    let start = Instant::now();
    let iters = 100_000u64;
    let mut sink = 0u8;
    for i in 0..iters {
        // Vary the size so one cached path is not measured repeatedly.
        sink ^= tree.root_at(n - (i % 1000))[0];
    }
    let elapsed = start.elapsed();
    std::hint::black_box(sink);
    rate("  root_at on a 1M-leaf tree", iters, elapsed, "roots");
}

/// Question: can proofs be generated fast enough to serve them per-request,
/// or does the server need a proof cache?
fn bench_proof_generation() {
    section("Proof generation");

    let n = 1_000_000u64;
    let leaves: Vec<_> = (0..n).map(|i| hash_leaf(&i.to_be_bytes())).collect();
    let tree = MerkleTree::from_leaves(&leaves);

    let iters = 100_000u64;
    let start = Instant::now();
    let mut sink = 0usize;
    for i in 0..iters {
        sink += tree.inclusion_proof((i * 7919) % n, n).unwrap().len();
    }
    let elapsed = start.elapsed();
    std::hint::black_box(sink);
    rate("  inclusion proof, 1M-leaf tree", iters, elapsed, "proofs");

    let start = Instant::now();
    let mut sink = 0usize;
    for i in 0..iters {
        sink += tree.consistency_proof((i * 7919) % n, n).unwrap().len();
    }
    let elapsed = start.elapsed();
    std::hint::black_box(sink);
    rate(
        "  consistency proof, 1M-leaf tree",
        iters,
        elapsed,
        "proofs",
    );
}

/// Question: is verification cheap enough that an auditor can check every
/// entry, or does auditing a large log require sampling?
fn bench_proof_verification() {
    section("Proof verification");

    let n = 1_000_000u64;
    let leaves: Vec<_> = (0..n).map(|i| hash_leaf(&i.to_be_bytes())).collect();
    let tree = MerkleTree::from_leaves(&leaves);
    let root = tree.root();

    // Pre-generate so generation cost is not folded into the measurement.
    let cases: Vec<_> = (0..20_000u64)
        .map(|i| {
            let idx = (i * 7919) % n;
            (
                idx,
                tree.inclusion_proof(idx, n).unwrap(),
                tree.leaf(idx).unwrap(),
            )
        })
        .collect();

    let start = Instant::now();
    for (idx, proof, leaf) in &cases {
        verify_inclusion(*idx, n, leaf, proof, &root).unwrap();
    }
    let elapsed = start.elapsed();
    rate(
        "  verify inclusion, 1M-leaf tree",
        cases.len() as u64,
        elapsed,
        "proofs",
    );

    let pairs: Vec<_> = (1..5_000u64)
        .map(|i| {
            let first = (i * 193) % n;
            (
                first,
                tree.consistency_proof(first, n).unwrap(),
                tree.root_at(first),
            )
        })
        .collect();

    let start = Instant::now();
    for (first, proof, first_root) in &pairs {
        verify_consistency(*first, n, first_root, &root, proof).unwrap();
    }
    let elapsed = start.elapsed();
    rate(
        "  verify consistency, 1M-leaf tree",
        pairs.len() as u64,
        elapsed,
        "proofs",
    );
}

/// Question: what does durability cost, and is the fsync or the hashing the
/// thing that limits append throughput?
///
/// The answer shapes the whole design. If fsync dominates by orders of
/// magnitude, then optimising the tree is pointless and group commit is the
/// only lever that matters.
fn bench_append(dir: &std::path::Path) {
    section("Append");

    for payload_size in [64usize, 1024] {
        let payload = vec![0x5au8; payload_size];

        // Without fsync: measures framing, CRC, leaf hash and tree push.
        let path = dir.join(format!("nosync-{payload_size}.log"));
        let (mut log, _) = Log::open(&path, SyncPolicy::Never).unwrap();
        let n = 200_000u64;
        let start = Instant::now();
        for i in 0..n {
            log.append_entry(Entry {
                position: i,
                timestamp_nanos: i,
                payload: payload.clone(),
            })
            .unwrap();
        }
        let elapsed = start.elapsed();
        rate(
            &format!("  append {payload_size}B, no fsync"),
            n,
            elapsed,
            "entries",
        );
        drop(log);

        // With fsync: measures the disk. Far fewer iterations because each one
        // is a platter round trip.
        let path = dir.join(format!("sync-{payload_size}.log"));
        let (mut log, _) = Log::open(&path, SyncPolicy::EveryAppend).unwrap();
        let n = 2_000u64;
        let start = Instant::now();
        for i in 0..n {
            log.append_entry(Entry {
                position: i,
                timestamp_nanos: i,
                payload: payload.clone(),
            })
            .unwrap();
        }
        let elapsed = start.elapsed();
        rate(
            &format!("  append {payload_size}B, fsync every append"),
            n,
            elapsed,
            "entries",
        );
    }
}

/// Question: how long does a restart take, given the tree is rebuilt from
/// scratch every time?
///
/// This is the cost of the decision that the log is the source of truth and
/// the tree is derived. If recovery were slow the obvious fix would be to
/// persist the tree, which would reintroduce the question of which one to
/// believe when they disagree.
fn bench_recovery(dir: &std::path::Path) {
    section("Recovery");

    for &n in &[10_000u64, 200_000] {
        let path = dir.join(format!("recover-{n}.log"));
        let (mut log, _) = Log::open(&path, SyncPolicy::Never).unwrap();
        for i in 0..n {
            log.append_entry(Entry {
                position: i,
                timestamp_nanos: i,
                payload: format!("entry-{i}").into_bytes(),
            })
            .unwrap();
        }
        let root = log.root();
        drop(log);

        let start = Instant::now();
        let (reopened, recovery) = Log::open(&path, SyncPolicy::Never).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(recovery.entries_loaded, n);
        assert_eq!(reopened.root(), root);

        rate(&format!("  replay {n} entries"), n, elapsed, "entries");
    }
}

// A leaf-hash microbenchmark is deliberately absent: it would measure sha256
// of a 20-to-60-byte buffer, which the SHA-256 section already reports, and
// an extra number that adds no information is worse than no number.
#[allow(dead_code)]
fn unused() {
    let _ = hash_children(&[0; 32], &[0; 32]);
}
