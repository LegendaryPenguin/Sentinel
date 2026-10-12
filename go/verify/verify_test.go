package verify

import (
	"bytes"
	"fmt"
	"testing"
)

// ---------------------------------------------------------------------------
// A reference tree, written here rather than in the package.
//
// The verifier under test is iterative and takes no tree. This is the
// recursive RFC 6962 definition transcribed directly, which is slow and
// obviously the same as the specification. Keeping it in the test file is
// deliberate: the shipped package stays verification-only, and the thing the
// verifier is checked against is a second implementation rather than itself.
// ---------------------------------------------------------------------------

// splitPoint is the largest power of two strictly less than n.
//
// "Strictly less than" is what makes the tree left-complete, so a left
// subtree's hash is final once complete. Splitting at n/2 instead produces a
// tree that is perfectly self-consistent and incompatible with every other
// RFC 6962 implementation.
func splitPoint(n uint64) uint64 {
	if n <= 1 {
		panic("splitPoint requires n > 1")
	}
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func referenceRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return HashEmpty()
	case 1:
		return leaves[0]
	default:
		k := splitPoint(uint64(len(leaves)))
		return HashChildren(referenceRoot(leaves[:k]), referenceRoot(leaves[k:]))
	}
}

// referenceInclusion is PATH(index, D[n]) from RFC 6962 §2.1.1, ordered
// leaf-first.
func referenceInclusion(leaves []Hash, index uint64) []Hash {
	if len(leaves) == 1 {
		return nil
	}
	k := splitPoint(uint64(len(leaves)))
	if index < k {
		return append(referenceInclusion(leaves[:k], index), referenceRoot(leaves[k:]))
	}
	return append(referenceInclusion(leaves[k:], index-k), referenceRoot(leaves[:k]))
}

// referenceConsistency is PROOF(m, D[n]) from RFC 6962 §2.1.2.
func referenceConsistency(leaves []Hash, m uint64) []Hash {
	if m == 0 || m == uint64(len(leaves)) {
		return nil
	}
	return subproof(leaves, m, true)
}

func subproof(leaves []Hash, m uint64, complete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return []Hash{referenceRoot(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subproof(leaves[:k], m, complete), referenceRoot(leaves[k:]))
	}
	return append(subproof(leaves[k:], m-k, false), referenceRoot(leaves[:k]))
}

func testLeaves(n uint64) []Hash {
	out := make([]Hash, n)
	for i := uint64(0); i < n; i++ {
		out[i] = HashLeaf([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return out
}

// ---------------------------------------------------------------------------
// Published vectors
// ---------------------------------------------------------------------------

func TestRFC6962Vectors(t *testing.T) {
	// Pinned in both languages. These are what makes the two
	// implementations compatible with the rest of the world rather than
	// merely with each other — a shared misreading of the RFC is the one
	// error a second implementation by the same author cannot catch.
	if got := HashEmpty().String(); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root = %s", got)
	}
	if got := HashLeaf(nil).String(); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Errorf("empty leaf = %s", got)
	}

	// The RFC's eight-leaf example tree.
	bodies := [][]byte{
		{},
		{0x00},
		{0x10},
		{0x20, 0x21},
		{0x30, 0x31},
		{0x40, 0x41, 0x42, 0x43},
		{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57},
		{0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f},
	}
	leaves := make([]Hash, len(bodies))
	for i, b := range bodies {
		leaves[i] = HashLeaf(b)
	}

	want := map[int]string{
		1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for size, expect := range want {
		if got := referenceRoot(leaves[:size]).String(); got != expect {
			t.Errorf("root at size %d = %s, want %s", size, got, expect)
		}
	}
}

func TestLeafAndNodeDomainsAreSeparate(t *testing.T) {
	// Build the exact collision the prefixes exist to prevent.
	a, b := HashLeaf([]byte("a")), HashLeaf([]byte("b"))
	node := HashChildren(a, b)
	leafOfConcat := HashLeaf(append(append([]byte{}, a[:]...), b[:]...))
	if node == leafOfConcat {
		t.Fatal("an internal node collides with a leaf: domain separation is broken")
	}
}

// ---------------------------------------------------------------------------
// Inclusion
// ---------------------------------------------------------------------------

func TestInclusionAtEveryIndexAndSize(t *testing.T) {
	// The exhaustive sweep is the test that matters. Odd sizes, sizes one
	// past a power of two, and the last leaf of a ragged tree are each where
	// a hand-written proof walk goes wrong, and spot-checking a few sizes
	// reliably misses at least one.
	for size := uint64(1); size <= 130; size++ {
		leaves := testLeaves(size)
		root := referenceRoot(leaves)
		for index := uint64(0); index < size; index++ {
			proof := referenceInclusion(leaves, index)
			if err := Inclusion(index, size, leaves[index], proof, root); err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
		}
	}
}

func TestInclusionRejectsTamperedLeaf(t *testing.T) {
	const size = 37
	leaves := testLeaves(size)
	root := referenceRoot(leaves)
	for index := uint64(0); index < size; index++ {
		proof := referenceInclusion(leaves, index)
		if err := Inclusion(index, size, HashLeaf([]byte("substituted")), proof, root); err == nil {
			t.Fatalf("index %d: a substituted leaf verified", index)
		}
	}
}

func TestInclusionRejectsMissingNodes(t *testing.T) {
	const size = 64
	leaves := testLeaves(size)
	root := referenceRoot(leaves)
	proof := referenceInclusion(leaves, 13)
	for drop := range proof {
		short := append(append([]Hash{}, proof[:drop]...), proof[drop+1:]...)
		if err := Inclusion(13, size, leaves[13], short, root); err == nil {
			t.Errorf("proof with node %d removed verified", drop)
		}
	}
}

func TestInclusionRejectsExtraNodes(t *testing.T) {
	const size = 64
	leaves := testLeaves(size)
	proof := append(referenceInclusion(leaves, 13), HashLeaf([]byte("extra")))
	err := Inclusion(13, size, leaves[13], proof, referenceRoot(leaves))
	if err == nil {
		t.Fatal("a proof with a trailing node verified")
	}
}

func TestInclusionRejectsReorderedNodes(t *testing.T) {
	// Order carries meaning: swapping siblings changes which side of the
	// concatenation each lands on.
	const size = 64
	leaves := testLeaves(size)
	root := referenceRoot(leaves)
	proof := referenceInclusion(leaves, 13)
	for i := 0; i+1 < len(proof); i++ {
		swapped := append([]Hash{}, proof...)
		swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
		if err := Inclusion(13, size, leaves[13], swapped, root); err == nil {
			t.Errorf("swapping nodes %d and %d still verified", i, i+1)
		}
	}
}

func TestInclusionRejectsCorruptedNodes(t *testing.T) {
	const size = 100
	leaves := testLeaves(size)
	root := referenceRoot(leaves)
	proof := referenceInclusion(leaves, 42)
	for i := range proof {
		for _, bit := range []uint{0, 7} {
			bad := append([]Hash{}, proof...)
			bad[i][0] ^= 1 << bit
			if err := Inclusion(42, size, leaves[42], bad, root); err == nil {
				t.Errorf("node %d bit %d corruption verified", i, bit)
			}
		}
	}
}

func TestInclusionProofDoesNotTransferBetweenIndices(t *testing.T) {
	const size = 50
	leaves := testLeaves(size)
	root := referenceRoot(leaves)
	proof := referenceInclusion(leaves, 10)
	for index := uint64(0); index < size; index++ {
		if index == 10 {
			continue
		}
		if err := Inclusion(index, size, leaves[index], proof, root); err == nil {
			t.Errorf("the proof for index 10 verified at index %d", index)
		}
	}
}

func TestInclusionRejectsStaleRoot(t *testing.T) {
	// A log answering a size-60 proof request with a size-50 root.
	leaves := testLeaves(60)
	proof := referenceInclusion(leaves, 3)
	stale := referenceRoot(leaves[:50])
	if err := Inclusion(3, 60, leaves[3], proof, stale); err == nil {
		t.Fatal("a stale root verified")
	}
}

func TestInclusionRejectsOutOfRangeIndex(t *testing.T) {
	leaves := testLeaves(10)
	err := Inclusion(10, 10, leaves[0], nil, referenceRoot(leaves))
	if err == nil {
		t.Fatal("index == size verified")
	}
}

// ---------------------------------------------------------------------------
// Consistency
// ---------------------------------------------------------------------------

func TestConsistencyAtEveryPairOfSizes(t *testing.T) {
	const max = 90
	leaves := testLeaves(max)
	for second := uint64(1); second <= max; second++ {
		secondRoot := referenceRoot(leaves[:second])
		for first := uint64(0); first <= second; first++ {
			firstRoot := referenceRoot(leaves[:first])
			proof := referenceConsistency(leaves[:second], first)
			if err := Consistency(first, second, firstRoot, secondRoot, proof); err != nil {
				t.Fatalf("%d -> %d: %v", first, second, err)
			}
		}
	}
}

func TestConsistencyRejectsRewrittenHistory(t *testing.T) {
	// Publish a root, then rewrite an old entry and keep appending. The new
	// tree is internally perfect; consistency with the published root is what
	// exposes it.
	const first, second = 20, 50
	honest := testLeaves(second)
	honestOldRoot := referenceRoot(honest[:first])

	forged := append([]Hash{}, honest...)
	forged[5] = HashLeaf([]byte("rewritten history"))
	forgedRoot := referenceRoot(forged)
	proof := referenceConsistency(forged, first)

	if err := Consistency(first, second, honestOldRoot, forgedRoot, proof); err == nil {
		t.Fatal("a rewritten history passed the consistency check")
	}
}

func TestConsistencyRejectsTruncatedHistory(t *testing.T) {
	// Dropping entries is the other half of rewriting them.
	const first, second = 30, 40
	full := testLeaves(second)
	proof := referenceConsistency(full, first)

	altered := append([]Hash{}, full[:first]...)
	altered[first-1] = HashLeaf([]byte("different last entry"))
	wrongOldRoot := referenceRoot(altered)

	if err := Consistency(first, second, wrongOldRoot, referenceRoot(full), proof); err == nil {
		t.Fatal("a mismatched old root passed the consistency check")
	}
}

func TestConsistencyRejectsCorruptedNodes(t *testing.T) {
	const first, second = 37, 100
	leaves := testLeaves(second)
	proof := referenceConsistency(leaves, first)
	for i := range proof {
		bad := append([]Hash{}, proof...)
		bad[i][HashLen-1] ^= 0x80
		err := Consistency(first, second, referenceRoot(leaves[:first]), referenceRoot(leaves), bad)
		if err == nil {
			t.Errorf("node %d corruption verified", i)
		}
	}
}

func TestConsistencyEqualSizesRequireEmptyProof(t *testing.T) {
	leaves := testLeaves(10)
	root := referenceRoot(leaves)
	if err := Consistency(10, 10, root, root, nil); err != nil {
		t.Fatalf("identical trees should be consistent: %v", err)
	}
	if err := Consistency(10, 10, root, root, []Hash{HashLeaf([]byte("x"))}); err == nil {
		t.Error("a non-empty proof for equal sizes was accepted")
	}
	if err := Consistency(10, 10, root, HashLeaf([]byte("other")), nil); err == nil {
		t.Error("equal sizes with different roots was accepted")
	}
}

func TestConsistencyEmptyFirstTreeRequiresEmptyRoot(t *testing.T) {
	leaves := testLeaves(10)
	root := referenceRoot(leaves)
	if err := Consistency(0, 10, HashEmpty(), root, nil); err != nil {
		t.Fatalf("every tree extends the empty tree: %v", err)
	}
	// The zero hash is the common and wrong choice for the empty root; an
	// attacker who can pass it can claim any new root extends "nothing".
	var zero Hash
	if err := Consistency(0, 10, zero, root, nil); err == nil {
		t.Error("the zero hash was accepted as the empty root")
	}
	if err := Consistency(0, 10, HashEmpty(), root, []Hash{HashLeaf([]byte("x"))}); err == nil {
		t.Error("a non-empty proof for an empty first tree was accepted")
	}
}

func TestConsistencyRejectsReversedSizes(t *testing.T) {
	leaves := testLeaves(10)
	err := Consistency(8, 5, referenceRoot(leaves[:8]), referenceRoot(leaves[:5]), nil)
	if err == nil {
		t.Fatal("reversed sizes verified")
	}
}

func TestProofLengthsAreLogarithmic(t *testing.T) {
	leaves := testLeaves(1024)
	for index := uint64(0); index < 1024; index++ {
		if n := len(referenceInclusion(leaves, index)); n != 10 {
			t.Fatalf("inclusion proof at %d has %d nodes, want 10", index, n)
		}
	}
	for first := uint64(1); first <= 1024; first++ {
		if n := len(referenceConsistency(leaves, first)); n > 11 {
			t.Fatalf("consistency proof %d -> 1024 has %d nodes", first, n)
		}
	}
}

// ---------------------------------------------------------------------------
// Canonical encoding
// ---------------------------------------------------------------------------

func TestCanonicalRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{{}, []byte("x"), {0x00, 0xff, 0x0a, 0x0d}} {
		e := Entry{Position: 7, TimestampNanos: 1_700_000_000_000_000_000, Payload: payload}
		got, err := ParseCanonical(e.Canonical())
		if err != nil {
			t.Fatalf("payload %q: %v", payload, err)
		}
		if got.Position != e.Position || got.TimestampNanos != e.TimestampNanos || !bytes.Equal(got.Payload, payload) {
			t.Errorf("round trip changed the entry: %+v", got)
		}
	}
}

func TestCanonicalRejectsTrailingBytes(t *testing.T) {
	// Without the length field a server could append padding and claim any
	// entry it liked while still hashing to a leaf in the tree.
	e := Entry{Position: 1, TimestampNanos: 2, Payload: []byte("abc")}
	if _, err := ParseCanonical(append(e.Canonical(), 0x00)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}

func TestCanonicalRejectsTruncation(t *testing.T) {
	e := Entry{Position: 1, TimestampNanos: 2, Payload: []byte("abc")}
	full := e.Canonical()
	for n := 0; n < len(full); n++ {
		if _, err := ParseCanonical(full[:n]); err == nil {
			t.Errorf("a %d-byte prefix was accepted", n)
		}
	}
}

func TestPositionAndTimestampAreBothHashed(t *testing.T) {
	// Neither may be silently revisable, so both must change the leaf.
	base := Entry{Position: 1, TimestampNanos: 100, Payload: []byte("same")}
	shifted := Entry{Position: 2, TimestampNanos: 100, Payload: []byte("same")}
	retimed := Entry{Position: 1, TimestampNanos: 101, Payload: []byte("same")}
	if HashLeaf(base.Canonical()) == HashLeaf(shifted.Canonical()) {
		t.Error("position does not affect the leaf hash")
	}
	if HashLeaf(base.Canonical()) == HashLeaf(retimed.Canonical()) {
		t.Error("timestamp does not affect the leaf hash")
	}
}

func TestParseHashRejectsWrongLength(t *testing.T) {
	h := HashLeaf([]byte("x"))
	if _, err := ParseHash(h.String()); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	for _, bad := range []string{"", "abc", h.String()[:63], h.String() + "0"} {
		if _, err := ParseHash(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := ParseHash("z" + h.String()[1:]); err == nil {
		t.Error("accepted a non-hex character")
	}
}
