# 🛡️ Sentinel

*An append-only transparency log where the interesting claim is not that it stores records, but that it cannot quietly change one — and that you do not have to take its word for it.*

Sentinel is a transparency log in **3,277 lines of Rust** and **1,944 lines of Go**, backed by **1,974 lines of tests** — **132 tests** across six packages, with the Rust side clean under `clippy` and the Go side clean under `-race`. It implements an append-only persistent log with crash recovery, an RFC 6962 Merkle tree, inclusion and consistency proofs, and an auditor that shares no code with the server it audits.

The thing I would point at: **the verifier builds with `CGO_ENABLED=0` and links nothing from the Rust core.** That is not a packaging detail, it is the entire premise. An auditor who has to run the log's own code to check the log has not checked anything.

```
$ ./scripts/demo.sh
...
verified 25 entries and 12 consistency proofs against root 6b7893d3… (size 25) in 23ms
the log at size 25 is an append-only extension of size 0

   flipped bit 6 of byte 305 of 916
   the server refused to start:
   | error="entry 8 at byte 288 is corrupt: checksum mismatch: want 0x44e34e89,
   |   got 0xd314a0a0 (the log is not safe to serve; it has been modified after the fact)"
```

## ✨ Why I Built It

I could describe a Merkle tree before I wrote this. I could not have told you why the empty tree's root is `SHA-256("")` rather than thirty-two zero bytes, and the answer turns out to be the difference between a verifier that works and one that accepts any history an attacker likes.

The gap I wanted to close was between *authenticated data structure* as a phrase and as a thing with edges. Most of the work turned out not to be the tree. It was the parts where two implementations have to agree exactly — serialization, odd tree sizes, what counts as a recoverable crash — and those are invisible until you build the second implementation and watch it disagree.

## 🔭 What It Does

**Appends, durably, and assigns identity itself.** Position and timestamp are chosen by the log, not the client. A client that could pick its own position could overwrite an entry; one that could pick its own timestamp could backdate a record the log is attesting to having seen. Both are hashed into the leaf, so neither is revisable after the fact.

**Hashes an RFC 6962 tree over the log.** Left-complete, domain-separated, deterministic. The tree is derived state — rebuilt from the log on every open, never persisted — so a disagreement between the log and the tree is impossible by construction rather than by care.

**Proves inclusion.** "Entry 37 is in the tree of 1,000 entries whose root is X", in ten hashes.

**Proves consistency.** "The tree of 1,000 entries extends the tree of 400 entries you saw last week." This is the one that detects a rewritten history; inclusion proofs cannot, because a rewritten log is internally perfect.

**Verifies independently.** A separate Go package and a static binary that fetch over HTTP and check everything, sharing no code and no hash implementation with the producer.

**Refuses to serve a log it cannot vouch for.** A complete record whose CRC fails is not a degraded read, it is a startup failure.

## 🧱 How I Built It

I built it in the order the dependencies actually run, which meant resisting the urge to start with the tree.

**Week 1 — the log, before any cryptography.** Durable append, monotonic positions, recovery on open. I wanted the persistence semantics settled before a hash function could hide a bug in them. The decision that paid off most was making the persisted log authoritative and the tree disposable: when the two could disagree, there would be no arbiter, and "which one is right" is not a question a transparency log gets to be unsure about.

**Week 2 — the tree.** `MerkleTree` keeps perfect-subtree hashes in `levels[i][j]`, covering leaves `[j·2^i, (j+1)·2^i)`. Because RFC 6962 splits at the largest power of two *strictly* below the node's width, every left subtree is perfect and its hash is final the moment it completes — so a cached hash never needs invalidating, only extending. Appends are amortised O(1) hashes; historical roots and proofs are O(log n) instead of O(n).

**Week 3 — proofs.** Generation follows the recursive RFC definitions almost literally, because the recursive form is the one that is visibly the same as the specification. Verification is iterative and takes no tree. That asymmetry is deliberate: if the two shared a tree walk, a tree bug would be invisible, because the proof and the check would be wrong in the same direction.

**Week 4 — the split, and the C ABI.** The Go service owns HTTP; the Rust core owns the log and the tree; `go/verify` and `go/audit` own verification and are forbidden from importing either. The boundary is a hand-written C header with caller-allocated buffers, status codes, and `catch_unwind` on every entry point — a Rust panic unwinding into C is undefined behaviour, and the tree's assertions are reachable from there via bad arguments.

**Week 5 — trying to break it.** Torn tails at every byte offset, mid-file corruption, spliced records, reordered and padded and truncated proofs, stale roots, and a server that lies in four specific ways.

### The decision I would defend hardest

**The Rust core implements SHA-256 by hand; the Go verifier uses `crypto/sha256`.**

This looks like dependency hygiene and is actually the test strategy. Two unrelated hash implementations agreeing on a root is evidence. One implementation agreeing with itself is not. Every cross-language test in `go/logstore` is therefore a real check on the hand-rolled compression function, and it costs 7.9× throughput, measured below.

What it does *not* buy is independence of the proof algorithms. Those are the same RFC algorithms written twice by the same person, which catches transcription errors and language-specific mistakes and would sail straight past a misreading of the specification. That is what the pinned published vectors are for, and it is why they are asserted in both languages.

## 🧪 How I Tried to Break It

**Exhaustive sweeps rather than spot checks.** Every index at every tree size up to 130, both languages, both proof types. Ragged right edges are where a hand-written proof walk goes wrong, and checking sizes 1, 10 and 100 reliably misses at least one.

**A torn tail at every possible byte.** The last record of a ten-entry log, truncated at each offset inside it. All must recover to nine entries, reproduce the nine-entry root exactly, shorten the file so the next append lands correctly, and still serve verifying proofs.

**A server that lies, four ways.** Correct-path tests only prove the auditor accepts honest answers. `service_test.go` wraps the real store in one that forges roots, pads canonical bytes, drops a proof node, and serves the neighbouring entry — and asserts the auditor refuses each. The substituted-entry case is caught by the position check before the proof is consulted, because the leaf commits to its own index.

**Architecture as a test.** `verify/independence_test.go` parses the package's own imports and fails if anything reaches the log, the bridge, or the service — including from test files, since "I just needed a fixture" is the realistic way that property dies. It also asserts the directory contains no cgo directives. The first version of that test failed on its own source code, which is funny exactly once.

**Domain separation, demonstrated not asserted.** A test builds the specific collision the prefixes exist to prevent — a leaf whose body is `left || right` of a real internal node — and checks the hashes differ.

### Four bugs worth recording

**`PayloadTooLarge` is a correct rejection and my test said it was a bug.** Corrupting byte 0 of a record flips the high byte of a big-endian length prefix, inflating the declared size past the cap. My corruption sweep enumerated `BadChecksum`, `Truncated` and `LengthMismatch` and panicked on anything else. The code was right; the test's idea of "all the ways this can be rejected" was incomplete. I had written the test to be exhaustive over corruption sites and forgot to be exhaustive over outcomes.

**The empty root is not the zero hash.** I had `[0u8; 32]` at first because it reads like the natural identity. It is exploitable: a verifier using zeros accepts a consistency proof from an empty tree against *any* root, because the attacker picks the claimed old root. Both verifiers now assert the zero hash is rejected there.

**Clippy found a real UB risk in the FFI, not a style nit.** `not_unsafe_ptr_arg_deref` on ten entry points. Marking them `unsafe extern "C"` changes nothing about the exported symbol or the ABI — it is Rust-side only — but it forces every caller, including my own tests, to acknowledge what they are doing. Silencing the lint would have been one line and would have thrown away the signal.

**`&payload[0]` panics on an empty slice, and Go passes nil for one.** An empty payload is a legal entry. Go hands a nil pointer with length zero across cgo, and `slice::from_raw_parts` requires a non-null aligned pointer even at length zero. The header now documents null-with-zero-length as accepted and the Rust side synthesises an empty slice.

## 📊 Benchmarks

Apple Silicon, release build, `cargo run --release --bin bench` and `go test -bench`. Medians over fixed iteration counts, no outlier rejection — where a number is too noisy to conclude from, it says so.

### Durability costs 1,327×, and that settles the design

| Operation | Rate |
|---|---|
| append 64 B, no fsync | 428,127 /sec |
| append 64 B, fsync every append | **322 /sec** |
| append 1 KiB, no fsync | 150,786 /sec |
| append 1 KiB, fsync every append | **323 /sec** |

One fsync is ~3.1 ms and the payload size does not matter, because the cost is a platter round trip and not the bytes. Two consequences I did not fully appreciate before measuring:

**Optimising the tree is pointless on the durable path.** At 322 appends/sec the tree contributes about 0.2% of the time. Group commit — batching N entries behind one fsync — is the only lever with real leverage, and it is not implemented. Knowing exactly which line costs the 1,327× is the part I took from this.

**The no-fsync numbers are the only place hashing shows up**, and there the 64 B and 1 KiB figures differ by 2.8×, which is the SHA-256 cost becoming visible once the disk is out of the way.

### Hand-rolled SHA-256 costs 7.9×

| Input | Rust (hand-rolled) | Go (`crypto/sha256`, ARMv8 SHA-2) | Ratio |
|---|---|---|---|
| 32 B | 81 MiB/s | 959 MiB/s | 11.8× |
| 256 B | 294 MiB/s | 2,764 MiB/s | 9.4× |
| 4 KiB | 422 MiB/s | 3,406 MiB/s | 8.1× |
| 1 MiB | 436 MiB/s | 3,462 MiB/s | **7.9×** |

This is the measured price of the zero-dependency decision and I am reporting it rather than defending it. The ratio is the hardware SHA extensions, not my loop being naive — no scalar implementation closes that gap. On the durable append path it is invisible; on a bulk tree rebuild it is the dominant cost.

### The subtree cache does what it claims

| Operation on a 1M-leaf tree | Rate |
|---|---|
| push (build) | 2,595,371 leaves/sec |
| `root_at` (historical root) | 231,368 /sec |
| generate inclusion proof | 472,184 /sec |
| generate consistency proof | 471,492 /sec |
| verify inclusion (Rust) | 118,492 /sec |
| verify consistency (Rust) | 86,351 /sec |
| verify inclusion (Go) | 465,517 /sec |
| verify consistency (Go) | 523,013 /sec |

`root_at` at 231k/sec on a million-leaf tree is the cache being real: an uncached recursive walk would be ~20 hashes against a million leaf reads. Build throughput staying flat from 100k to 1M confirms the amortised O(1) claim rather than assuming it.

**The Go verifier is 3.9× faster than the Rust one**, which inverts the expectation and has one cause: verification is almost entirely `hash_children`, so it inherits the 7.9× SHA-256 gap and claws some back on Rust's side from cheaper bounds handling. It is also the number that matters most, because the Go verifier is the one an auditor runs — at ~2.1 µs per proof, auditing a million-entry log end to end is about 2 seconds of CPU plus a million HTTP round trips, and the round trips are the problem.

### Recovery is linear and fast enough to not matter

| Entries replayed | Rate |
|---|---|
| 10,000 | 845,425 /sec |
| 200,000 | 1,555,788 /sec |

A 200k-entry log rebuilds its tree in 129 ms. This is the number that justifies not persisting the tree: the thing persisting it would buy is ~0.1 s of startup, and the thing it would cost is having two sources of truth that can disagree. The higher rate at the larger size is page-cache warmth, not superlinearity.

## 📚 What I Learned

**Two implementations are a test strategy, not redundancy.** I expected the second implementation to be tedious bookkeeping. It found things: the byte-order question I would not have thought to ask, the empty-root exploit, and the fact that "the verifier must be handed the exact bytes that were hashed" is a format requirement rather than a convenience. A single implementation cannot be wrong in a way it can notice.

**Domain separation is one byte and an entire class of attack.** `0x00` for leaves, `0x01` for nodes. Without it a leaf whose body happens to equal `left || right` of an internal node is that node, and a prover can present interior nodes as entries. I understood this as a hygiene rule; it is load-bearing, and I now write the collision as a test rather than the rule as a comment.

**The difference between a torn write and corruption is a product decision disguised as an implementation detail.** Both are "the bytes are not what I expect". One was never acknowledged to anyone and discarding it loses nothing. The other was acknowledged, and skipping it to keep the log usable would renumber every later entry and change every root — performing the exact history rewrite the system exists to detect. The honest answer is to refuse to start, and that is a harder sell than it sounds when the alternative is a log that appears to work.

**`strictly` less than, in "largest power of two strictly less than n", is the whole tree.** Split at `n/2` and you get a structure that is internally perfect, passes every self-consistency test, and is incompatible with every other RFC 6962 implementation. Nothing in a single-implementation test suite can tell you. Published vectors can, and that is the only reason they are in there.

**A proof that verifies is not the same as a proof of the thing you asked about.** My first auditor checked the proof and returned the entry. It would have accepted a server that answered a different question — a valid proof for entry 4 in response to a request about entry 3. The fix is four checks before the cryptography: the response describes the request, the canonical bytes decode, their internal position matches, and re-encoding reproduces them byte-for-byte. The leaf committing to its own position is what makes the third one possible.

## ⚖️ What I Do Not Claim

- **There are no signatures, and this is the single largest gap.** A real transparency log signs its tree heads, so a client can tell the operator's log from a man-in-the-middle serving a self-consistent fake. Sentinel has no key. Everything here proves *internal* consistency of whatever history you were served; it cannot prove you were served the right one. `audit.SignedRoot` is named aspirationally and says so in its doc comment.
- **No gossip, so a split view is undetectable.** A log can serve history A to you and history B to someone else, and both can be perfectly consistent. Detecting that requires auditors comparing roots with each other, which is a protocol I did not build. This is the second-largest gap and it is not a small one.
- **No authentication on append.** Anyone who can reach the port can write to the log.
- **No TLS.**
- **Single writer, single process, no file lock.** Two servers pointed at one log file will corrupt it, and nothing detects or prevents that. An advisory `flock` is the obvious fix and is absent.
- **The whole tree is in memory** — 32 bytes per leaf plus the internal cache, plus an 8-byte file offset per entry, so roughly 72 bytes per entry. A billion-entry log needs ~72 GB of RAM. Payloads stay on disk, which is the part that grows without bound, but the tree does not shard.
- **Timestamps are server wall-clock and nothing enforces monotonicity.** If the clock steps backwards, entry *n+1* can carry an earlier timestamp than entry *n*. The tree does not care — position is what orders the log — but a reader treating timestamps as ordered would be wrong, and no check rejects it.
- **A corrupted length field in the *final* record is indistinguishable from a torn write.** The inflated length makes the remainder look incomplete, and the CRC cannot be checked without first trusting the length. Recovery truncates and reports the byte count so the event is visible, but it cannot be classified. A second length copy would fix it.
- **Group commit is not implemented**, so durable throughput is 322 appends/sec, 1,327× below the non-durable path. The fix is well understood and absent.
- **The proof algorithms are not independently designed**, only independently written. Same author, same RFC, twice. That catches transcription and language-specific errors and would not catch a misreading of the specification.
- **No fuzzing.** The adversarial tests are hand-written cases I thought of. A structure-aware fuzzer over the storage framing and the proof decoder is the obvious next step and would probably find something.
- **`verify_integrity` reopens and replays the whole file** under a read lock, which is O(n) and blocks appends for the duration. Fine at the sizes here; not a thing to call on a hot server.
- **No deletion, no pruning, no sharding, no replication.** One log, one file, one machine, forever.
- **I did not test against another implementation's proofs.** The published vectors pin the tree hashes, which is the part most likely to diverge, but feeding Sentinel a proof generated by Trillian or `certificate-transparency-go` would be a stronger check and I have not done it.

## 🛠️ Tech Stack

- **Rust 1.99**, no dependencies. `Cargo.toml` has no `[dependencies]` section at all — SHA-256, CRC-32C, the tree, the proofs and the storage framing are the project, so importing them would leave nothing behind.
- **Go 1.24**, standard library only. No `require` block.
- **cgo** over a hand-written C ABI (`sentinel-core/include/sentinel.h`), `staticlib` crate type.
- `overflow-checks = true` in release: a wrapped position or tree size would produce a valid-looking proof for the wrong entry, which is precisely the failure mode this project is about.

## 🚀 Setup

```bash
# Build the core and both binaries
cd sentinel-core && cargo build --release && cd ..
cd go && go build ./... && cd ..

# The auditor, deliberately without cgo
cd go && CGO_ENABLED=0 go build -o sentinel-verify ./cmd/sentinel-verify

# Everything, including the cross-language and adversarial suites
cd sentinel-core && cargo test && cargo clippy --all-targets && cd ..
cd go && go test -race ./... && cd ..

# End to end: serve, append, audit, then tamper and watch it refuse
./scripts/demo.sh
```

Running it by hand:

```bash
go run ./cmd/sentinel-server -addr 127.0.0.1:8080 -log /tmp/sentinel.log

./sentinel-verify root   -server http://127.0.0.1:8080
./sentinel-verify append -server http://127.0.0.1:8080 -data "hello"
./sentinel-verify audit  -server http://127.0.0.1:8080
./sentinel-verify monitor -server http://127.0.0.1:8080 -size 0 \
  -root e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

`sentinel-verify` exits 0 when verified, 1 when it could not complete, 2 on misuse, and **3 specifically when verification failed** — so a cron job can tell a network blip from evidence of tampering.

## 🗺️ Repository Map

```
sentinel-core/            Rust: the log, the tree, the proofs
  src/sha256.rs           hand-rolled SHA-256, and why
  src/crc32c.rs           storage framing integrity only
  src/hash.rs             RFC 6962 domain separation, left-complete split
  src/record.rs           canonical bytes (hashed) vs storage frame (private)
  src/tree.rs             derived Merkle state, perfect-subtree cache
  src/proof.rs            inclusion + consistency, generation and verification
  src/log.rs              the persisted source of truth, and recovery
  src/ffi.rs              C ABI: no Rust types, no panics, fixed buffers
  src/bin/bench.rs        the numbers above
  include/sentinel.h      the hand-written contract

go/
  verify/                 INDEPENDENT verifier — stdlib only, no cgo
  audit/                  HTTP auditor that trusts nothing it is told
  logstore/               the only package that links Rust
  service/                HTTP handlers
  cmd/sentinel-server/    serve one log
  cmd/sentinel-verify/    audit a log; builds with CGO_ENABLED=0

docs/FORMAT.md            the contract both implementations are written against
scripts/demo.sh           build, serve, audit, tamper, refuse
```

## 📖 References

- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) — Certificate Transparency. §2.1 is the tree, §2.1.1–2.1.2 are the proofs, and the test vectors in §2.1.3 are what keep this compatible with the world.
- [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) — CT 2.0, whose iterative verification algorithms are the ones implemented here.
- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) — SHA-256.
- Crosby & Wallach, [*Efficient Data Structures for Tamper-Evident Logging*](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf) (USENIX Security 2009) — where the history-tree framing comes from.

## 📄 License

MIT. See [LICENSE](LICENSE).
