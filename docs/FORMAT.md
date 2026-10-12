# Sentinel wire and storage formats

This document is the contract. `sentinel-core` implements it in Rust and
`go/verify` implements it again in Go, from this text rather than from the
Rust source. If the two disagree, this file decides which one is wrong.

Everything is **big-endian**. That is a deliberate choice and not a matter of
taste: canonical bytes cross a language boundary and get hashed, and a
byte-order disagreement between producer and verifier manifests as "the proof
does not verify" with nothing in either implementation looking wrong. One
order everywhere removes the class of bug.

---

## 1. Canonical entry encoding

The bytes that are hashed into a leaf. **This encoding may never change.**
Every proof the log has ever issued is a statement about these bytes.

```
offset  size  field
0       8     position          u64, zero-based index in the log
8       8     timestamp_nanos   u64, nanoseconds since the Unix epoch
16      4     payload_len       u32, length of the payload in bytes
20      n     payload           arbitrary bytes
```

Total length is `20 + payload_len`.

Three things are worth justifying.

**`payload_len` is present even though the payload runs to the end of the
buffer.** Without it, a future encoding that appended a field could produce
canonical bytes identical to some existing entry's. A format that can be
extended is one where that eventually happens, and the cost of preventing it
is four bytes.

**`position` is inside the hashed bytes.** A leaf therefore commits to its own
index. This is what makes a server unable to serve entry 7's bytes in response
to a request about entry 3 — the substitution is caught by comparing the
decoded position against the requested one, before the proof is consulted.
It also means two entries with identical payloads at different positions are
different leaves.

**`timestamp_nanos` is inside the hashed bytes, and is assigned by the
server.** The log commits to when it claims to have seen a record and cannot
revise that later without breaking every proof it has already issued. A client
cannot choose it, because a client that could would be able to backdate.

A verifier must reject canonical bytes whose `payload_len` disagrees with the
buffer length, in either direction. Accepting trailing bytes would let a
server pad real entry bytes and claim a different entry.

---

## 2. Tree hashing (RFC 6962 §2.1)

```
MTH({})       = SHA-256("")
MTH({d})      = SHA-256(0x00 || d)
MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                where k is the largest power of two strictly less than n
```

`d` is the canonical encoding from §1.

**The prefixes are load-bearing.** Without domain separation, a leaf whose body
happens to equal `left || right` of an internal node hashes to the same value
as that node, which lets a prover present an interior node as a leaf and claim
an entry is in the log that never was. One byte closes the entire class.

**The empty root is `SHA-256("")`**, which is
`e3b0c442...7852b855`. It is *not* the zero hash. A verifier that uses zeros
here will accept a consistency proof from an empty tree against an
attacker-chosen root, because the attacker gets to pick the "old root" freely.

**`k` is strictly less than `n`.** This makes the tree left-complete: the left
subtree of any node is perfect, so its hash is final the moment it is complete
and never changes as the log grows. That property is what makes consistency
proofs short and incremental hashing possible. Splitting at `n/2` instead
produces a tree that is perfectly self-consistent and incompatible with every
other RFC 6962 implementation.

### Pinned vectors

Both implementations assert these. They are the only defence against the two
of them sharing a misreading of the specification.

| Input | Value |
|---|---|
| `MTH({})` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `MTH({""})` | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |

For the RFC's eight-leaf example tree (leaf bodies `""`, `00`, `10`, `2021`,
`3031`, `40414243`, `5051525354555657`, `606162…6f`):

| Size | Root |
|---|---|
| 1 | `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` |
| 2 | `fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125` |
| 3 | `aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77` |
| 4 | `d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7` |
| 8 | `5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328` |

---

## 3. Proofs

### Inclusion

`PATH(m, D[n])` per RFC 6962 §2.1.1, ordered **leaf-first**: the sibling
nearest the leaf comes first. Length is at most `ceil(log2(n))`.

Verification walks up from the leaf carrying `(node, last)` — the index at the
current level and the index of the rightmost node at that level. When
`node == last` the node is on the tree's right edge and has no sibling, so it
is carried up without consuming a proof node. That pair is how the walk knows
the tree's shape without having the tree.

A verifier must reject:

- a proof with fewer nodes than the walk needs;
- a proof with nodes left over after the walk completes (trailing nodes are the
  shape of a prover feeling out what a verifier will tolerate);
- `index >= size`.

### Consistency

`PROOF(m, D[n])` per RFC 6962 §2.1.2.

The proof is **empty** when `m == 0` or `m == n`, and a verifier must *require*
emptiness in those cases rather than merely tolerate it. It must also check
that `m == 0` is accompanied by the empty root from §2.

Verification reconstructs **both** roots from the same nodes. Rebuilding only
the new root shows the proof is well-formed against the new tree, which is not
the claim being made; the claim is that the old root is embedded in the new
one. The step where the old reconstruction declines to absorb a right-hand
sibling is where "appended" is distinguished from "rewritten".

---

## 4. Storage framing

Private to the log file. Unlike §1 this may change freely, because nothing
outside the process ever sees it.

```
offset  size  field
0       4     body_len   u32, bytes of canonical encoding that follow
4       n     body       the canonical encoding from §1
4+n     4     crc32c     CRC-32C over bytes [0, 4+n)
```

The CRC covers the length prefix. A corrupted length that is not covered can
steer the reader onto a boundary where some other record's bytes happen to
checksum correctly, and the reader then reports success on a log it has
misparsed.

Records are concatenated with no padding. A record's `position` field must
equal its ordinal in the file; a mismatch means the file has been spliced
rather than merely damaged, and is fatal.

### Recovery

Two failures look superficially alike and must be treated differently.

A **torn tail** is an incomplete final record: the process died between
`write` and `fsync`. The entry was never acknowledged to any client and no
published root contains it, so the bytes are discarded and the file truncated.
Recoverable, and reported so an operator knows it happened.

A **corrupt record** is a complete, framed record whose CRC does not match.
Those bytes were acknowledged and are now something other than what was
written. Skipping it to keep the log usable would silently renumber every
later entry and change every root — which is precisely the history rewrite the
project exists to detect. Fatal. The server refuses to start.

**Known limitation.** A corrupted `body_len` in the *final* record is
indistinguishable from a torn write: the inflated length makes the remaining
bytes look like an incomplete record, and the CRC cannot be checked without
first trusting the length. Recovery truncates and reports the byte count, so
the event is visible, but it cannot be classified. Fixing it properly needs a
second length copy or a per-record header checksum.

---

## 5. HTTP API

Hashes are lowercase hex; payloads and canonical bytes are base64 (standard
encoding, padded). Hex for hashes because roots get pasted into tickets and
compared by eye; base64 for payloads because they are arbitrary bytes and hex
would double an already-large body.

| Method | Path | Parameters | Returns |
|---|---|---|---|
| `POST` | `/append` | `{"payload": base64}` | `position`, `timestamp_nanos`, `size`, `root` |
| `GET` | `/root` | `size` (optional) | `size`, `root` |
| `GET` | `/entry` | `position` | `position`, `timestamp_nanos`, `payload`, `canonical` |
| `GET` | `/proof/inclusion` | `position`, `tree_size` (optional) | `leaf_index`, `tree_size`, `root`, `proof[]`, `canonical` |
| `GET` | `/proof/consistency` | `first`, `second` | `first_size`, `second_size`, `first_root`, `second_root`, `proof[]` |
| `GET` | `/health` | — | `size`, `root` |

`size` and `root` in the `/append` response describe the tree **that append
produced** — the root is taken at `position + 1`, not at the log's current
size, which may already have moved. Reporting the current size would hand a
client a root for a tree that does not contain the entry it just wrote at the
size it was told.

`proof` is always a JSON array, `[]` when empty, never `null`. A `null`
invites a client to treat an empty consistency proof as absent rather than as
the meaningful value it is.

An auditor must pass `tree_size` explicitly. A proof whose size was chosen by
the server is a proof about a tree the auditor cannot name, and cannot be
rechecked later.
