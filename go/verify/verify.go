// Package verify checks Sentinel's proofs without trusting Sentinel.
//
// Nothing in this package imports the log, the cgo bridge, or anything that
// links sentinel-core. That constraint is the package's entire reason for
// existing and is enforced by a test in verify_independence_test.go rather
// than by a comment, because a comment does not survive someone needing a
// helper function in a hurry.
//
// What "independent" does and does not mean here, stated plainly because the
// word gets oversold:
//
//   - The hash is genuinely independent. sentinel-core implements SHA-256 by
//     hand; this package uses crypto/sha256 from the Go standard library.
//     Two unrelated implementations agreeing on a root is real evidence. If
//     the hand-rolled one has a bug, the cross-language tests fail.
//
//   - The canonical encoding is reimplemented from the specification in
//     docs/FORMAT.md rather than shared, so a producer that silently changes
//     its framing stops verifying instead of quietly redefining the format.
//
//   - The proof algorithms are *not* independent in design. They are the same
//     RFC 6962 algorithms, written a second time in a different language by
//     the same person. That catches transcription errors and language-
//     specific mistakes. It does not catch a misreading of the RFC, and I am
//     not going to claim it does. Guarding against that needs the published
//     test vectors, which is why they are pinned in both languages.
package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// HashLen is the length of every hash in the protocol.
const HashLen = 32

// Hash is a tree hash. A fixed-size array rather than a slice so that
// equality is value equality and a nil can never masquerade as a root.
type Hash [HashLen]byte

// Domain separation prefixes from RFC 6962 §2.1.
//
// Without them, a leaf whose body happens to equal left||right of an internal
// node hashes identically to that node, which lets a prover present an
// interior node as a leaf. One byte closes it.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// HashEmpty is the root of a tree with no leaves: SHA-256 of the empty
// string.
//
// Not the zero hash. That distinction is load-bearing — a verifier that uses
// zeros here will accept a consistency proof from an empty tree against a
// forged root, because the attacker can choose the "old root" freely.
func HashEmpty() Hash {
	return sha256.Sum256(nil)
}

// HashLeaf returns SHA-256(0x00 || entry), where entry is the canonical
// encoding of a log entry.
func HashLeaf(entry []byte) Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(entry)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashChildren returns SHA-256(0x01 || left || right).
func HashChildren(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash decodes 64 hex characters.
//
// A wrong length is an error rather than a zero-pad: a verifier handed a
// truncated root must fail, not silently compare against something else.
func ParseHash(s string) (Hash, error) {
	var out Hash
	if len(s) != HashLen*2 {
		return out, fmt.Errorf("verify: hash must be %d hex characters, got %d", HashLen*2, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("verify: hash is not hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// Errors are distinguishable on purpose. "Proof invalid" tells an operator
// nothing; the difference between a malformed proof and a well-formed proof
// that recomputes the wrong root is the difference between a client bug and a
// log that is lying.
var (
	// ErrRootMismatch means the proof is well-formed and recomputes a
	// different root. This is the one that means tampering.
	ErrRootMismatch = errors.New("verify: recomputed root does not match")
	// ErrProofTooShort means fewer nodes than the tree size requires.
	ErrProofTooShort = errors.New("verify: proof too short")
	// ErrProofTooLong means trailing nodes were supplied. Rejected rather
	// than ignored: extra nodes are the shape of a prover probing what a
	// verifier will tolerate.
	ErrProofTooLong = errors.New("verify: proof too long")
	// ErrIndexOutOfRange means the leaf index is not inside the tree.
	ErrIndexOutOfRange = errors.New("verify: leaf index outside tree")
	// ErrSizesReversed means a consistency proof was requested backwards.
	ErrSizesReversed = errors.New("verify: first size exceeds second")
	// ErrExpectedEmptyProof means a proof was supplied where the protocol
	// requires none.
	ErrExpectedEmptyProof = errors.New("verify: expected an empty proof")
)

// Inclusion reports whether leafHash sits at index in a tree of size entries
// whose root is root.
//
// Takes no tree and no log — everything it needs is in the arguments, which
// is what makes it usable by an auditor who has only ever seen the server's
// HTTP responses.
//
// The index/last pair is how the walk knows whether a node has a sibling
// without materialising the tree: when node == last the node is on the tree's
// right edge and is carried up unchanged.
func Inclusion(index, size uint64, leafHash Hash, proof []Hash, root Hash) error {
	if index >= size {
		return fmt.Errorf("%w: index %d, size %d", ErrIndexOutOfRange, index, size)
	}

	node, last := index, size-1
	computed := leafHash
	used := 0

	for last > 0 {
		if node%2 == 1 {
			// Right child: the sibling is on the left.
			if used >= len(proof) {
				return fmt.Errorf("%w: %d nodes for a tree of %d", ErrProofTooShort, len(proof), size)
			}
			computed = HashChildren(proof[used], computed)
			used++
		} else if node < last {
			// Left child that has a sibling.
			if used >= len(proof) {
				return fmt.Errorf("%w: %d nodes for a tree of %d", ErrProofTooShort, len(proof), size)
			}
			computed = HashChildren(computed, proof[used])
			used++
		}
		// node == last and even: no sibling at this level, carry upward.
		node /= 2
		last /= 2
	}

	if used != len(proof) {
		return fmt.Errorf("%w: %d supplied, %d consumed", ErrProofTooLong, len(proof), used)
	}
	if computed != root {
		return fmt.Errorf("%w: computed %s, expected %s", ErrRootMismatch, computed, root)
	}
	return nil
}

// Consistency reports whether a tree of second entries rooted at secondRoot is
// an append-only extension of a tree of first entries rooted at firstRoot.
//
// Both roots are recomputed from the same proof nodes, and that is the load-
// bearing part. A verifier that only rebuilds the new root has shown the proof
// is well-formed against the new tree, which is not the claim; the claim is
// that the old root is embedded in the new one.
func Consistency(first, second uint64, firstRoot, secondRoot Hash, proof []Hash) error {
	if first > second {
		return fmt.Errorf("%w: %d > %d", ErrSizesReversed, first, second)
	}
	if first == second {
		if len(proof) != 0 {
			return fmt.Errorf("%w for equal sizes, got %d nodes", ErrExpectedEmptyProof, len(proof))
		}
		if firstRoot != secondRoot {
			return fmt.Errorf("%w: equal sizes with different roots", ErrRootMismatch)
		}
		return nil
	}
	if first == 0 {
		// Every tree extends the empty tree, so there is nothing to prove —
		// but a proof must not be smuggled in alongside that fact, and the
		// claimed old root must actually be the empty root.
		if len(proof) != 0 {
			return fmt.Errorf("%w for an empty first tree, got %d nodes", ErrExpectedEmptyProof, len(proof))
		}
		if firstRoot != HashEmpty() {
			return fmt.Errorf("%w: first size 0 requires the empty root", ErrRootMismatch)
		}
		return nil
	}

	node, last := first-1, second-1
	// Climb to the root of the old tree's rightmost complete subtree. Those
	// levels lie entirely inside the old tree and contribute no proof nodes.
	for node%2 == 1 {
		node /= 2
		last /= 2
	}

	used := 0
	var old, new_ Hash
	if node > 0 {
		// The old tree's right edge is not a node of the new tree, so the
		// prover must supply it; it seeds both reconstructions.
		if len(proof) == 0 {
			return fmt.Errorf("%w: no seed node", ErrProofTooShort)
		}
		old, new_ = proof[0], proof[0]
		used = 1
	} else {
		// first is a power of two: the old root is itself a node of the new
		// tree and need not be resent.
		old, new_ = firstRoot, firstRoot
	}

	for node > 0 {
		if last == 0 {
			return fmt.Errorf("%w: ran out of levels", ErrProofTooShort)
		}
		if node%2 == 1 {
			if used >= len(proof) {
				return fmt.Errorf("%w: %d nodes", ErrProofTooShort, len(proof))
			}
			// A left sibling both trees share.
			old = HashChildren(proof[used], old)
			new_ = HashChildren(proof[used], new_)
			used++
		} else if node < last {
			if used >= len(proof) {
				return fmt.Errorf("%w: %d nodes", ErrProofTooShort, len(proof))
			}
			// A right sibling that exists only in the new tree. The old
			// reconstruction deliberately does not absorb it: this is the step
			// that distinguishes "appended" from "rewritten".
			new_ = HashChildren(new_, proof[used])
			used++
		}
		node /= 2
		last /= 2
	}

	if old != firstRoot {
		return fmt.Errorf("%w: old root %s, expected %s", ErrRootMismatch, old, firstRoot)
	}

	// Fold in whatever the new tree grew above the old tree's root.
	for last > 0 {
		if used >= len(proof) {
			return fmt.Errorf("%w: %d nodes", ErrProofTooShort, len(proof))
		}
		new_ = HashChildren(new_, proof[used])
		used++
		last /= 2
	}

	if new_ != secondRoot {
		return fmt.Errorf("%w: new root %s, expected %s", ErrRootMismatch, new_, secondRoot)
	}
	if used != len(proof) {
		return fmt.Errorf("%w: %d supplied, %d consumed", ErrProofTooLong, len(proof), used)
	}
	return nil
}

// Entry is a decoded log entry.
type Entry struct {
	Position       uint64
	TimestampNanos uint64
	Payload        []byte
}

// canonicalHeader is position + timestamp + payload length.
const canonicalHeader = 8 + 8 + 4

// ParseCanonical decodes the canonical bytes that were hashed into a leaf.
//
// Reimplemented from docs/FORMAT.md rather than shared with the producer. The
// point is that if the producer's framing changes, verification breaks loudly
// instead of the format silently becoming "whatever the producer emits".
//
// Big-endian throughout, which is the format's choice precisely because these
// bytes cross a language boundary: a byte-order disagreement between producer
// and verifier shows up as "the proof does not verify" with nothing in either
// implementation looking wrong.
func ParseCanonical(b []byte) (Entry, error) {
	if len(b) < canonicalHeader {
		return Entry{}, fmt.Errorf("verify: canonical entry is %d bytes, need at least %d", len(b), canonicalHeader)
	}
	e := Entry{
		Position:       binary.BigEndian.Uint64(b[0:8]),
		TimestampNanos: binary.BigEndian.Uint64(b[8:16]),
	}
	declared := int(binary.BigEndian.Uint32(b[16:20]))
	available := len(b) - canonicalHeader
	if declared != available {
		return Entry{}, fmt.Errorf("verify: canonical entry declares %d payload bytes, has %d", declared, available)
	}
	e.Payload = make([]byte, available)
	copy(e.Payload, b[canonicalHeader:])
	return e, nil
}

// Canonical re-encodes an entry.
//
// Present so a verifier can check that the bytes it was handed are the
// canonical encoding of the entry it thinks it received, rather than
// arbitrary bytes that happen to hash to a leaf in the tree. A server could
// otherwise append trailing padding and claim any entry it liked.
func (e Entry) Canonical() []byte {
	out := make([]byte, 0, canonicalHeader+len(e.Payload))
	out = binary.BigEndian.AppendUint64(out, e.Position)
	out = binary.BigEndian.AppendUint64(out, e.TimestampNanos)
	out = binary.BigEndian.AppendUint32(out, uint32(len(e.Payload)))
	return append(out, e.Payload...)
}
