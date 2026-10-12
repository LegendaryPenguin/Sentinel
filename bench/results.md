# Benchmark results

Apple Silicon (18 logical cores), macOS 25.6, release builds.

- Rust: `cd sentinel-core && cargo run --release --bin bench`
- Go: `cd go && CGO_ENABLED=0 go test -run=XXX -bench=. ./verify/`

**Method, stated so the numbers can be discounted appropriately.** Medians over
fixed iteration counts. No criterion, no outlier rejection, no confidence
intervals — the zero-dependency rule applies to the benchmark harness too, and
the cost is statistical rigour. Single run per cell unless noted. Treat
same-order differences as noise; the conclusions below only lean on
differences of 2× or more, and the cells where that is not safe say so.

The fsync numbers in particular are a property of this SSD and this
filesystem, not of the code.

---

## 1. Durability dominates everything — 1,327×

| Operation | Rate | Per op |
|---|---|---|
| append 64 B, no fsync | 428,127 /sec | 2.3 µs |
| append 64 B, fsync every append | **322 /sec** | **3.1 ms** |
| append 1 KiB, no fsync | 150,786 /sec | 6.6 µs |
| append 1 KiB, fsync every append | **323 /sec** | **3.1 ms** |

The 64 B and 1 KiB fsync figures are within 0.3% of each other, which is the
finding: **the cost is the round trip, not the bytes.** A 16× larger payload
changes durable throughput not at all.

### What this settles

**Tree and hashing optimisation is pointless on the durable path.** At 3.1 ms
per append, the 2.3 µs of framing, CRC, leaf hash and tree push is 0.07% of
the time. Every microsecond I could win in `tree.rs` is noise against one
fsync.

**Group commit is the only lever with leverage, and it is not implemented.**
Batching N entries behind a single fsync would move durable throughput toward
the non-durable ceiling. The ceiling is 428k/sec at 64 B, so the headroom is
three orders of magnitude. This is the largest unexploited performance fact in
the repository and I am recording it rather than claiming the current number
is good.

**The no-fsync column is the only place hashing is visible.** 64 B → 1 KiB
costs 2.8× there (2.3 µs → 6.6 µs), which is SHA-256 over 16× the bytes
showing up once the disk is out of the way. That ratio is also a rough check
on the SHA-256 numbers in §2 being real.

---

## 2. Hand-rolled SHA-256 costs 7.9×

| Input size | Rust, hand-rolled | Go `crypto/sha256` | Ratio |
|---|---|---|---|
| 32 B | 81.4 MiB/s | 958.6 MiB/s | 11.8× |
| 256 B | 294.2 MiB/s | 2,764.4 MiB/s | 9.4× |
| 4 KiB | 421.5 MiB/s | 3,405.8 MiB/s | 8.1× |
| 1 MiB | 435.8 MiB/s | 3,461.9 MiB/s | **7.9×** |

Go's `crypto/sha256` uses the ARMv8 SHA-2 instructions. The Rust
implementation is scalar FIPS 180-4 with no SIMD and no assembly.

**This is the measured price of the zero-dependency decision.** I am reporting
it rather than defending it. Two honest observations:

- **The gap is the hardware, not a naive loop.** No scalar implementation
  closes an 8× gap against dedicated SHA instructions. Rewriting the inner
  loop more cleverly would win percentages, not multiples. Closing it properly
  means `std::arch` intrinsics with a runtime feature check, which is a real
  piece of work and is not here.
- **The small-input ratio is worse (11.8×) because of fixed overhead**, not
  because the compression function is worse there. At 32 B both
  implementations do one block; Go's is a few instructions and Rust's is 64
  rounds of scalar arithmetic.

**Where it matters:** bulk tree rebuilds and recovery. **Where it does not:**
the durable append path, per §1, where it is 0.07% of the time.

---

## 3. The subtree cache is real

All on a 1,000,000-leaf tree.

| Operation | Rate | Per op |
|---|---|---|
| push (incremental build) | 2,595,371 /sec | 385 ns |
| `root_at` (historical root) | 231,368 /sec | 4.3 µs |
| generate inclusion proof | 472,184 /sec | 2.1 µs |
| generate consistency proof | 471,492 /sec | 2.1 µs |

Build throughput across sizes, which is the amortised-O(1) claim:

| Leaves | Rate |
|---|---|
| 1,000 | 2,295,774 /sec |
| 100,000 | 2,636,511 /sec |
| 1,000,000 | 2,595,371 /sec |

**Flat from 100k to 1M**, so `push` is not quietly recomputing the right edge.
The 1,000-leaf cell is 13% lower and that is measurement noise at a 0.4 ms
total runtime, not a real effect — it is too short to time this way and should
be discounted.

`root_at` at 4.3 µs on a million leaves is the cache doing its job: the
uncached path would touch every leaf. Proof generation at 2.1 µs is fast enough
to serve per-request, so **no proof cache is needed**, which was the question
the benchmark was written to answer.

Inclusion and consistency generation are within 0.15% of each other. They walk
the same number of levels and hit the same cache, so that is expected rather
than suspicious.

---

## 4. Verification — and the result that inverted my expectation

| Operation | Rust | Go | Go advantage |
|---|---|---|---|
| verify inclusion, 1M-leaf tree | 118,492 /sec (8.4 µs) | 465,549 /sec (2.15 µs) | **3.9×** |
| verify consistency, 1M-leaf tree | 86,351 /sec (11.6 µs) | 523,013 /sec (1.91 µs) | **6.1×** |

**The Go verifier is several times faster than the Rust one.** I expected the
opposite and the cause is §2: verification is almost entirely `hash_children`
calls, so it inherits the full SHA-256 gap. Twenty levels of a million-leaf
tree is twenty 65-byte hashes, and Go does each of those ~9× faster.

**This is the number that matters most**, because the Go verifier is the one an
auditor actually runs. At 2.15 µs per inclusion proof, verifying every entry of
a million-entry log is ~2.1 seconds of CPU. The bottleneck for a real audit is
therefore a million HTTP round trips, not the cryptography — which is why
`audit.Monitor` exists and needs exactly one proof regardless of how much the
log grew.

**Caveat on the consistency row.** Go's consistency verification coming out
*faster* than its inclusion verification (1.91 vs 2.15 µs) is not something I
can explain from first principles — consistency does strictly more work in the
general case. The likely cause is the distribution of `first` values in the
benchmark favouring short proofs, which would make this an artifact of my test
data rather than a property of the algorithm. I have not chased it down, and
the two should be treated as "roughly equal" rather than ranked.

---

## 5. Recovery is linear, and fast enough to justify not persisting the tree

| Entries replayed | Rate | Total |
|---|---|---|
| 10,000 | 845,425 /sec | 12 ms |
| 200,000 | 1,555,788 /sec | 129 ms |

Replay reads every record, checks every CRC, re-hashes every leaf and rebuilds
the tree from scratch.

**This is the measurement that justifies the central design decision.**
Persisting the tree would save ~0.13 s of startup on a 200k-entry log. It would
cost having two durable sources of truth that can disagree, with no arbiter
when they do. At 129 ms the trade is not close.

The *higher* rate at the larger size is page-cache warmth from the preceding
write loop, not superlinear scaling. Both cells are the same O(n) path; do not
read a trend into two points that differ by cache state.

---

## Summary

| Claim | Status |
|---|---|
| fsync dominates append cost | **1,327×**, confirmed, payload-size-independent |
| group commit would be the big win | implied by the above, **not implemented** |
| hand-rolled SHA-256 is slower | **7.9×** at 1 MiB, confirmed, hardware-caused |
| subtree cache makes `root_at` cheap | confirmed, 4.3 µs on 1M leaves |
| build is amortised O(1) per leaf | confirmed, flat 100k → 1M |
| proofs can be served per-request | confirmed, 2.1 µs, no cache needed |
| the Rust verifier is faster than Go's | **refuted** — Go is 3.9× faster |
| recovery is cheap enough to not persist the tree | confirmed, 129 ms for 200k |
| Go consistency beats Go inclusion | **too noisy / likely a test-data artifact** |
