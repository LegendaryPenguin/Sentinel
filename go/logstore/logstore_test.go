package logstore_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/LegendaryPenguin/sentinel/logstore"
	"github.com/LegendaryPenguin/sentinel/verify"
)

// These are the tests the whole two-language structure exists for.
//
// Everything on the Rust side is already covered by Rust tests, and
// everything in package verify is covered by Go tests against a Go reference
// tree. Neither of those can catch the failure that actually matters here: the
// producer and the verifier agreeing with themselves and disagreeing with
// each other. A byte-order slip in the canonical encoding, a SHA-256 bug in
// the hand-rolled implementation, or a proof emitted in the wrong order all
// pass both halves and fail here.
//
// Note the asymmetry: proofs are *generated* by Rust and *checked* by Go,
// never the reverse. A verifier that only ever checks proofs it generated
// itself is checking its own arithmetic.

func tempLog(t *testing.T, name string) (*logstore.Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".log")
	log, rec, err := logstore.Open(path, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if rec.EntriesLoaded != 0 || rec.TailBytesDiscarded != 0 {
		t.Fatalf("fresh log reported recovery %+v", rec)
	}
	t.Cleanup(log.Close)
	return log, path
}

// toVerifyHash converts across the two packages' deliberately separate hash
// types. The conversion is explicit everywhere rather than hidden in a shared
// type, which is the point: the real interface between the two sides is
// 32 bytes, and nothing else is shared.
func toVerifyHash(h logstore.Hash) verify.Hash {
	var out verify.Hash
	copy(out[:], h[:])
	return out
}

func toVerifyProof(proof []logstore.Hash) []verify.Hash {
	out := make([]verify.Hash, len(proof))
	for i, h := range proof {
		out[i] = toVerifyHash(h)
	}
	return out
}

func TestEmptyLogRootMatchesTheGoEmptyRoot(t *testing.T) {
	// The empty root is SHA-256 of the empty string, computed by two
	// independent SHA-256 implementations. If the hand-rolled Rust one is
	// wrong, this is the first thing that fails.
	log, _ := tempLog(t, "empty")
	root, err := log.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if toVerifyHash(root) != verify.HashEmpty() {
		t.Fatalf("empty root = %s, Go computes %s", root, verify.HashEmpty())
	}
}

func TestAppendAssignsSequentialPositions(t *testing.T) {
	log, _ := tempLog(t, "positions")
	for i := uint64(0); i < 50; i++ {
		e, err := log.Append([]byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if e.Position != i {
			t.Fatalf("append %d got position %d", i, e.Position)
		}
		if e.TimestampNanos == 0 {
			t.Fatalf("append %d got a zero timestamp", i)
		}
	}
	size, err := log.Size()
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size != 50 {
		t.Fatalf("size = %d", size)
	}
}

func TestEmptyPayloadIsAcceptedAcrossTheBoundary(t *testing.T) {
	// Go passes a nil pointer for an empty slice, which is the calling
	// convention the C header documents and a real source of crashes if the
	// Rust side builds a slice from it blindly.
	log, _ := tempLog(t, "empty-payload")
	for i := 0; i < 3; i++ {
		if _, err := log.Append(nil); err != nil {
			t.Fatalf("append nil: %v", err)
		}
		if _, err := log.Append([]byte{}); err != nil {
			t.Fatalf("append empty: %v", err)
		}
	}
	size, _ := log.Size()
	if size != 6 {
		t.Fatalf("size = %d, want 6", size)
	}
}

func TestLeafHashesAgreeAcrossLanguages(t *testing.T) {
	// The canonical bytes come from Rust; the leaf hash is computed in Go
	// with crypto/sha256. A single-entry tree's root is its leaf hash, which
	// gives a direct comparison with no tree arithmetic in between.
	log, _ := tempLog(t, "leaf-agree")
	if _, err := log.Append([]byte("the only entry")); err != nil {
		t.Fatalf("append: %v", err)
	}
	canonical, err := log.EntryCanonical(0)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	root, _ := log.Root()
	if verify.HashLeaf(canonical) != toVerifyHash(root) {
		t.Fatalf("Go leaf hash %s != Rust root %s", verify.HashLeaf(canonical), root)
	}

	// And the canonical bytes must parse under the Go decoder, which was
	// written from the format document rather than shared with the producer.
	entry, err := verify.ParseCanonical(canonical)
	if err != nil {
		t.Fatalf("Go cannot parse the producer's canonical bytes: %v", err)
	}
	if entry.Position != 0 || string(entry.Payload) != "the only entry" {
		t.Fatalf("decoded entry is wrong: %+v", entry)
	}
	// Re-encoding must reproduce the exact bytes, or the two sides disagree
	// about the format even though the hash happened to match.
	if string(entry.Canonical()) != string(canonical) {
		t.Fatal("Go re-encoding does not reproduce the producer's canonical bytes")
	}
}

func TestRustProofsVerifyInGoAtEveryIndexAndSize(t *testing.T) {
	// The exhaustive cross-language sweep. 80 entries is 3,240 proof
	// verifications, which runs in well under a second and covers every
	// ragged-right-edge shape that a proof walk gets wrong.
	const max = 80
	log, _ := tempLog(t, "cross-inclusion")
	for i := uint64(0); i < max; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	for size := uint64(1); size <= max; size++ {
		root, err := log.RootAt(size)
		if err != nil {
			t.Fatalf("root_at(%d): %v", size, err)
		}
		for index := uint64(0); index < size; index++ {
			proof, err := log.InclusionProof(index, size)
			if err != nil {
				t.Fatalf("inclusion_proof(%d, %d): %v", index, size, err)
			}
			canonical, err := log.EntryCanonical(index)
			if err != nil {
				t.Fatalf("canonical(%d): %v", index, err)
			}
			err = verify.Inclusion(index, size, verify.HashLeaf(canonical),
				toVerifyProof(proof), toVerifyHash(root))
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
		}
	}
}

func TestRustConsistencyProofsVerifyInGoAtEveryPair(t *testing.T) {
	const max = 60
	log, _ := tempLog(t, "cross-consistency")
	for i := uint64(0); i < max; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	for second := uint64(1); second <= max; second++ {
		secondRoot, err := log.RootAt(second)
		if err != nil {
			t.Fatalf("root_at(%d): %v", second, err)
		}
		for first := uint64(0); first <= second; first++ {
			firstRoot, err := log.RootAt(first)
			if err != nil {
				t.Fatalf("root_at(%d): %v", first, err)
			}
			proof, err := log.ConsistencyProof(first, second)
			if err != nil {
				t.Fatalf("consistency_proof(%d, %d): %v", first, second, err)
			}
			err = verify.Consistency(first, second,
				toVerifyHash(firstRoot), toVerifyHash(secondRoot), toVerifyProof(proof))
			if err != nil {
				t.Fatalf("%d -> %d: %v", first, second, err)
			}
		}
	}
}

func TestAppendOnlyPropertyAcrossTheBoundary(t *testing.T) {
	// Every root the log ever published must still be derivable, and every
	// pair must still prove consistent, after many more appends. This is the
	// property an auditor who saved an old root depends on.
	log, _ := tempLog(t, "append-only")
	var published []logstore.Hash
	root, _ := log.Root()
	published = append(published, root)

	for i := uint64(0); i < 70; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
		r, err := log.Root()
		if err != nil {
			t.Fatalf("root: %v", err)
		}
		published = append(published, r)
	}

	final := published[len(published)-1]
	finalSize := uint64(len(published) - 1)
	for size, want := range published {
		got, err := log.RootAt(uint64(size))
		if err != nil {
			t.Fatalf("root_at(%d): %v", size, err)
		}
		if got != want {
			t.Fatalf("root for size %d changed: %s -> %s", size, want, got)
		}
		proof, err := log.ConsistencyProof(uint64(size), finalSize)
		if err != nil {
			t.Fatalf("consistency_proof(%d, %d): %v", size, finalSize, err)
		}
		err = verify.Consistency(uint64(size), finalSize,
			toVerifyHash(want), toVerifyHash(final), toVerifyProof(proof))
		if err != nil {
			t.Fatalf("consistency %d -> %d: %v", size, finalSize, err)
		}
	}
}

func TestReopenReproducesEveryHistoricalRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.log")

	var published []logstore.Hash
	{
		log, _, err := logstore.Open(path, false)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		r, _ := log.Root()
		published = append(published, r)
		for i := 0; i < 65; i++ {
			if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
				t.Fatalf("append: %v", err)
			}
			r, _ := log.Root()
			published = append(published, r)
		}
		log.Close()
	}

	log, rec, err := logstore.Open(path, false)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer log.Close()
	if rec.EntriesLoaded != 65 {
		t.Fatalf("recovered %d entries, want 65", rec.EntriesLoaded)
	}
	if rec.TailBytesDiscarded != 0 {
		t.Fatalf("discarded %d tail bytes from a cleanly closed log", rec.TailBytesDiscarded)
	}
	// Recovery that reproduces only the final root is not enough: proofs
	// already issued against earlier roots must still verify.
	for size, want := range published {
		got, err := log.RootAt(uint64(size))
		if err != nil {
			t.Fatalf("root_at(%d): %v", size, err)
		}
		if got != want {
			t.Fatalf("root for size %d not reproduced after reopen", size)
		}
	}
}

func TestTornTailIsRecoveredAndReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "torn.log")
	{
		log, _, err := logstore.Open(path, true)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		for i := 0; i < 12; i++ {
			if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		log.Close()
	}

	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Chop bytes off the end, simulating death between write and fsync.
	// Recovery must land on a shorter but internally consistent log whose
	// proofs still verify in Go.
	for _, cut := range []int{1, 5, 17} {
		truncated := filepath.Join(t.TempDir(), fmt.Sprintf("torn-%d.log", cut))
		if err := os.WriteFile(truncated, full[:len(full)-cut], 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		log, rec, err := logstore.Open(truncated, false)
		if err != nil {
			t.Fatalf("cut %d: open: %v", cut, err)
		}
		if rec.TailBytesDiscarded == 0 {
			t.Errorf("cut %d: recovery reported no discarded bytes", cut)
		}
		if rec.EntriesLoaded != 11 {
			t.Errorf("cut %d: recovered %d entries, want 11", cut, rec.EntriesLoaded)
		}

		// The recovered log must still be provable end to end.
		size, _ := log.Size()
		root, _ := log.RootAt(size)
		for index := uint64(0); index < size; index++ {
			proof, err := log.InclusionProof(index, size)
			if err != nil {
				t.Fatalf("cut %d index %d: %v", cut, index, err)
			}
			canonical, err := log.EntryCanonical(index)
			if err != nil {
				t.Fatalf("cut %d canonical %d: %v", cut, index, err)
			}
			err = verify.Inclusion(index, size, verify.HashLeaf(canonical),
				toVerifyProof(proof), toVerifyHash(root))
			if err != nil {
				t.Fatalf("cut %d index %d: %v", cut, index, err)
			}
		}

		// And appending after recovery must continue the same tree.
		if _, err := log.Append([]byte("after recovery")); err != nil {
			t.Fatalf("cut %d: append after recovery: %v", cut, err)
		}
		log.Close()
	}
}

func TestMidFileCorruptionIsRefusedAtOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.log")
	{
		log, _, err := logstore.Open(path, true)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		for i := 0; i < 12; i++ {
			if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		log.Close()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Flip a bit inside an early record's payload. The framing still parses,
	// which is what makes this the dangerous case: without the CRC the server
	// would come up healthy and serve a different history.
	data[len(data)/3] ^= 0x40
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	log, _, err := logstore.Open(path, false)
	if err == nil {
		size, _ := log.Size()
		log.Close()
		t.Fatalf("a corrupt log opened with %d entries", size)
	}
}

func TestConcurrentAppendsAndReadsAreSerialised(t *testing.T) {
	// Run under -race. The Rust Log has no internal locking, so this is
	// checking the Go-side RWMutex actually mirrors Rust's borrow rules
	// across the boundary. Without the write lock on Append, two goroutines
	// compute position from the same stale length.
	log, _ := tempLog(t, "concurrent")

	const writers, perWriter = 8, 40
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := log.Append([]byte(fmt.Sprintf("w%d-%d", w, i))); err != nil {
					t.Errorf("append: %v", err)
					return
				}
			}
		}(w)
	}
	// Readers run concurrently to exercise the read path against a moving
	// tree.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, err := log.Root(); err != nil {
					t.Errorf("root: %v", err)
					return
				}
				if _, err := log.Size(); err != nil {
					t.Errorf("size: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	size, err := log.Size()
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size != writers*perWriter {
		t.Fatalf("size = %d, want %d: appends raced", size, writers*perWriter)
	}

	// Every position must be present exactly once, which is the property a
	// lost update would break.
	seen := make(map[uint64]bool, size)
	for i := uint64(0); i < size; i++ {
		canonical, err := log.EntryCanonical(i)
		if err != nil {
			t.Fatalf("canonical(%d): %v", i, err)
		}
		e, err := verify.ParseCanonical(canonical)
		if err != nil {
			t.Fatalf("parse(%d): %v", i, err)
		}
		if seen[e.Position] {
			t.Fatalf("position %d appears twice", e.Position)
		}
		seen[e.Position] = true
	}

	// And the whole thing still verifies.
	root, _ := log.RootAt(size)
	for i := uint64(0); i < size; i++ {
		proof, _ := log.InclusionProof(i, size)
		canonical, _ := log.EntryCanonical(i)
		if err := verify.Inclusion(i, size, verify.HashLeaf(canonical),
			toVerifyProof(proof), toVerifyHash(root)); err != nil {
			t.Fatalf("index %d: %v", i, err)
		}
	}
}

func TestOutOfRangeRequestsAreTypedErrors(t *testing.T) {
	log, _ := tempLog(t, "errors")
	for i := 0; i < 4; i++ {
		if _, err := log.Append([]byte("x")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	if _, err := log.RootAt(99); !errors.Is(err, logstore.ErrNotFound) {
		t.Errorf("root_at past the end: got %v, want ErrNotFound", err)
	}
	if _, err := log.InclusionProof(0, 99); !errors.Is(err, logstore.ErrNotFound) {
		t.Errorf("proof past the end: got %v, want ErrNotFound", err)
	}
	if _, err := log.InclusionProof(9, 4); !errors.Is(err, logstore.ErrProof) {
		t.Errorf("index outside a valid size: got %v, want ErrProof", err)
	}
	if _, err := log.ConsistencyProof(3, 2); !errors.Is(err, logstore.ErrProof) {
		t.Errorf("reversed sizes: got %v, want ErrProof", err)
	}
	if _, err := log.EntryCanonical(99); !errors.Is(err, logstore.ErrNotFound) {
		t.Errorf("entry past the end: got %v, want ErrNotFound", err)
	}
}

func TestClosedLogReturnsErrClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "closed.log")
	log, _, err := logstore.Open(path, false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	log.Close()
	log.Close() // idempotent

	if _, err := log.Size(); !errors.Is(err, logstore.ErrClosed) {
		t.Errorf("Size after close: %v", err)
	}
	if _, err := log.Append([]byte("x")); !errors.Is(err, logstore.ErrClosed) {
		t.Errorf("Append after close: %v", err)
	}
	if _, err := log.Root(); !errors.Is(err, logstore.ErrClosed) {
		t.Errorf("Root after close: %v", err)
	}
	if _, err := log.InclusionProof(0, 0); !errors.Is(err, logstore.ErrClosed) {
		t.Errorf("InclusionProof after close: %v", err)
	}
}

func TestVerifyIntegrityOnAHealthyLog(t *testing.T) {
	log, _ := tempLog(t, "integrity")
	for i := 0; i < 30; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	n, err := log.VerifyIntegrity()
	if err != nil {
		t.Fatalf("verify_integrity: %v", err)
	}
	if n != 30 {
		t.Fatalf("replayed %d entries, want 30", n)
	}
}

func TestDurableAppendPath(t *testing.T) {
	// The fsync-per-append path is the default in production and must not be
	// exercised only implicitly.
	path := filepath.Join(t.TempDir(), "durable.log")
	log, _, err := logstore.Open(path, true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 100; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("durable-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	root, _ := log.Root()
	log.Close()

	reopened, rec, err := logstore.Open(path, true)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if rec.EntriesLoaded != 100 {
		t.Fatalf("recovered %d, want 100", rec.EntriesLoaded)
	}
	got, _ := reopened.Root()
	if got != root {
		t.Fatal("root changed across a durable reopen")
	}
}

func TestLargePayloadsCrossTheBoundary(t *testing.T) {
	// Exercises the multi-block SHA-256 path and a canonical buffer larger
	// than any fixed stack buffer would be.
	log, _ := tempLog(t, "large")
	sizes := []int{0, 1, 63, 64, 65, 4096, 1 << 20}
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		if _, err := log.Append(payload); err != nil {
			t.Fatalf("append %d bytes: %v", n, err)
		}
	}

	size, _ := log.Size()
	root, _ := log.RootAt(size)
	for i := uint64(0); i < size; i++ {
		canonical, err := log.EntryCanonical(i)
		if err != nil {
			t.Fatalf("canonical(%d): %v", i, err)
		}
		e, err := verify.ParseCanonical(canonical)
		if err != nil {
			t.Fatalf("parse(%d): %v", i, err)
		}
		if len(e.Payload) != sizes[i] {
			t.Fatalf("entry %d has %d payload bytes, want %d", i, len(e.Payload), sizes[i])
		}
		proof, _ := log.InclusionProof(i, size)
		if err := verify.Inclusion(i, size, verify.HashLeaf(canonical),
			toVerifyProof(proof), toVerifyHash(root)); err != nil {
			t.Fatalf("index %d (%d bytes): %v", i, sizes[i], err)
		}
	}
}
