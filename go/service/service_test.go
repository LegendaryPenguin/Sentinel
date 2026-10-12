package service_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LegendaryPenguin/sentinel/audit"
	"github.com/LegendaryPenguin/sentinel/logstore"
	"github.com/LegendaryPenguin/sentinel/service"
	"github.com/LegendaryPenguin/sentinel/verify"
)

// quietLogger keeps the expected-error tests from filling the test output
// with the errors they are asserting on.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------------------------------------------------------------------------
// End to end: real Rust-backed log, real HTTP, independent Go auditor.
//
// This is the test that exercises the arrangement the project is actually
// about. Everything in the chain is the production path except that the
// server is an httptest listener.
// ---------------------------------------------------------------------------

func realServer(t *testing.T) (*httptest.Server, *logstore.Log) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentinel.log")
	log, _, err := logstore.Open(path, false)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	t.Cleanup(log.Close)

	srv := httptest.NewServer(service.New(log, quietLogger()).Routes())
	t.Cleanup(srv.Close)
	return srv, log
}

func TestEndToEndAuditOfARealLog(t *testing.T) {
	srv, _ := realServer(t)
	client := audit.New(srv.URL)
	ctx := context.Background()

	const n = 40
	for i := 0; i < n; i++ {
		position, size, err := client.Append(ctx, []byte(fmt.Sprintf("record-%d", i)))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if position != uint64(i) || size != uint64(i+1) {
			t.Fatalf("append %d returned position %d size %d", i, position, size)
		}
	}

	report, err := client.AuditAll(ctx)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if report.Size != n {
		t.Errorf("audited size %d, want %d", report.Size, n)
	}
	if report.EntriesVerified != n {
		t.Errorf("verified %d entries, want %d", report.EntriesVerified, n)
	}
	if report.ConsistencyPairs == 0 {
		t.Error("no consistency proofs were checked")
	}
}

func TestMonitorAcrossGrowth(t *testing.T) {
	// The operation a repeat auditor runs: one proof, regardless of how much
	// the log grew, showing the new history extends the saved one.
	srv, _ := realServer(t)
	client := audit.New(srv.URL)
	ctx := context.Background()

	saved, err := client.Root(ctx)
	if err != nil {
		t.Fatalf("initial root: %v", err)
	}
	if saved.Size != 0 || saved.Root != verify.HashEmpty() {
		t.Fatalf("fresh log reported size %d root %s", saved.Size, saved.Root)
	}

	for round := 0; round < 6; round++ {
		for i := 0; i < 7; i++ {
			if _, _, err := client.Append(ctx, []byte(fmt.Sprintf("r%d-%d", round, i))); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		next, err := client.Monitor(ctx, saved)
		if err != nil {
			t.Fatalf("round %d: monitor: %v", round, err)
		}
		if next.Size <= saved.Size {
			t.Fatalf("round %d: size did not grow: %d -> %d", round, saved.Size, next.Size)
		}
		saved = next
	}
}

func TestEntryPayloadsRoundTripThroughHTTP(t *testing.T) {
	srv, _ := realServer(t)
	client := audit.New(srv.URL)
	ctx := context.Background()

	// Awkward payloads: empty, NULs, invalid UTF-8, and something long enough
	// to span several SHA-256 blocks.
	payloads := [][]byte{
		{},
		{0x00},
		{0xff, 0xfe, 0x00, 0x0a, 0x0d},
		[]byte(strings.Repeat("long ", 500)),
	}
	for _, p := range payloads {
		if _, _, err := client.Append(ctx, p); err != nil {
			t.Fatalf("append %d bytes: %v", len(p), err)
		}
	}

	root, err := client.Root(ctx)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	for i, want := range payloads {
		entry, err := client.VerifyInclusion(ctx, uint64(i), root.Size, root.Root)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if string(entry.Payload) != string(want) {
			t.Errorf("entry %d payload round-tripped wrong (%d vs %d bytes)",
				i, len(entry.Payload), len(want))
		}
	}
}

// ---------------------------------------------------------------------------
// A lying server
//
// Correct-path tests only show the auditor accepts honest answers. These wrap
// the real store in one that tampers in a specific way and assert the auditor
// refuses — which is the property that actually matters.
// ---------------------------------------------------------------------------

type tamperStore struct {
	service.Store
	// forgeRoot replaces every root with an attacker-chosen one.
	forgeRoot *logstore.Hash
	// padCanonical appends a byte to served canonical bytes.
	padCanonical bool
	// dropProofNode removes the first node of every inclusion proof.
	dropProofNode bool
	// shiftEntry serves position+1's bytes for any request.
	shiftEntry bool
}

func (s tamperStore) Root() (logstore.Hash, error) {
	if s.forgeRoot != nil {
		return *s.forgeRoot, nil
	}
	return s.Store.Root()
}

func (s tamperStore) RootAt(size uint64) (logstore.Hash, error) {
	if s.forgeRoot != nil {
		return *s.forgeRoot, nil
	}
	return s.Store.RootAt(size)
}

func (s tamperStore) EntryCanonical(position uint64) ([]byte, error) {
	if s.shiftEntry {
		if b, err := s.Store.EntryCanonical(position + 1); err == nil {
			return b, nil
		}
	}
	b, err := s.Store.EntryCanonical(position)
	if err != nil {
		return nil, err
	}
	if s.padCanonical {
		return append(b, 0x00), nil
	}
	return b, nil
}

func (s tamperStore) InclusionProof(index, size uint64) ([]logstore.Hash, error) {
	proof, err := s.Store.InclusionProof(index, size)
	if err != nil {
		return nil, err
	}
	if s.dropProofNode && len(proof) > 0 {
		return proof[1:], nil
	}
	return proof, nil
}

func tamperServer(t *testing.T, mutate func(*tamperStore)) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sentinel.log")
	log, _, err := logstore.Open(path, false)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	t.Cleanup(log.Close)
	for i := 0; i < 20; i++ {
		if _, err := log.Append([]byte(fmt.Sprintf("record-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	store := tamperStore{Store: log}
	mutate(&store)
	srv := httptest.NewServer(service.New(store, quietLogger()).Routes())
	t.Cleanup(srv.Close)
	return srv
}

func TestAuditorRejectsAForgedRoot(t *testing.T) {
	forged := logstore.Hash{}
	for i := range forged {
		forged[i] = 0xab
	}
	srv := tamperServer(t, func(s *tamperStore) { s.forgeRoot = &forged })

	_, err := audit.New(srv.URL).AuditAll(context.Background())
	if err == nil {
		t.Fatal("the auditor accepted a forged root")
	}
	if !errors.Is(err, verify.ErrRootMismatch) {
		t.Errorf("want a root mismatch, got %v", err)
	}
}

func TestAuditorRejectsPaddedCanonicalBytes(t *testing.T) {
	// A server appending a byte to the real entry bytes. The padded version
	// hashes to a different leaf, so the proof fails — but the auditor should
	// catch it earlier, at the re-encoding check, with a clearer error.
	srv := tamperServer(t, func(s *tamperStore) { s.padCanonical = true })

	_, err := audit.New(srv.URL).AuditAll(context.Background())
	if err == nil {
		t.Fatal("the auditor accepted padded canonical bytes")
	}
}

func TestAuditorRejectsAShortenedProof(t *testing.T) {
	srv := tamperServer(t, func(s *tamperStore) { s.dropProofNode = true })

	_, err := audit.New(srv.URL).AuditAll(context.Background())
	if err == nil {
		t.Fatal("the auditor accepted a proof with a node removed")
	}
}

func TestAuditorRejectsASubstitutedEntry(t *testing.T) {
	// The leaf commits to its own position, so serving entry 4's bytes for a
	// request about entry 3 is caught by the position check before the proof
	// is even consulted.
	srv := tamperServer(t, func(s *tamperStore) { s.shiftEntry = true })

	_, err := audit.New(srv.URL).AuditAll(context.Background())
	if err == nil {
		t.Fatal("the auditor accepted a substituted entry")
	}
	if !errors.Is(err, audit.ErrServerMisbehaved) {
		t.Errorf("want ErrServerMisbehaved, got %v", err)
	}
}

func TestAuditorRejectsAShrinkingLog(t *testing.T) {
	srv, _ := realServer(t)
	client := audit.New(srv.URL)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, _, err := client.Append(ctx, []byte("x")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	// Claim to have previously seen a larger log than exists now.
	saved := audit.SignedRoot{Size: 99, Root: verify.HashEmpty()}
	if _, err := client.Monitor(ctx, saved); err == nil {
		t.Fatal("the auditor accepted a log that shrank")
	}
}

// ---------------------------------------------------------------------------
// Handler-level behaviour, against a fake store
// ---------------------------------------------------------------------------

// fakeStore is a minimal in-memory implementation built on the exported hash
// primitives in package verify. Used for the request-validation and
// error-mapping tests, where driving the real log into each failure would be
// contrived.
type fakeStore struct {
	leaves    []verify.Hash
	canonical [][]byte
	fail      error
}

func (f *fakeStore) Size() (uint64, error) {
	if f.fail != nil {
		return 0, f.fail
	}
	return uint64(len(f.leaves)), nil
}

func (f *fakeStore) Append(payload []byte) (logstore.Entry, error) {
	if f.fail != nil {
		return logstore.Entry{}, f.fail
	}
	e := verify.Entry{Position: uint64(len(f.leaves)), TimestampNanos: 1, Payload: payload}
	c := e.Canonical()
	f.canonical = append(f.canonical, c)
	f.leaves = append(f.leaves, verify.HashLeaf(c))
	return logstore.Entry{Position: e.Position, TimestampNanos: e.TimestampNanos}, nil
}

func (f *fakeStore) Root() (logstore.Hash, error) { return f.RootAt(uint64(len(f.leaves))) }

func (f *fakeStore) RootAt(size uint64) (logstore.Hash, error) {
	if f.fail != nil {
		return logstore.Hash{}, f.fail
	}
	if size > uint64(len(f.leaves)) {
		return logstore.Hash{}, fmt.Errorf("fake: %w", logstore.ErrNotFound)
	}
	return toLogstore(mth(f.leaves[:size])), nil
}

func (f *fakeStore) InclusionProof(index, size uint64) ([]logstore.Hash, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if size > uint64(len(f.leaves)) {
		return nil, fmt.Errorf("fake: %w", logstore.ErrNotFound)
	}
	if index >= size {
		return nil, fmt.Errorf("fake: %w", logstore.ErrProof)
	}
	return toLogstoreAll(path(f.leaves[:size], index)), nil
}

func (f *fakeStore) ConsistencyProof(first, second uint64) ([]logstore.Hash, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if first > second {
		return nil, fmt.Errorf("fake: %w", logstore.ErrProof)
	}
	if second > uint64(len(f.leaves)) {
		return nil, fmt.Errorf("fake: %w", logstore.ErrNotFound)
	}
	return nil, nil // not exercised by the handler tests
}

func (f *fakeStore) EntryCanonical(position uint64) ([]byte, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	if position >= uint64(len(f.canonical)) {
		return nil, fmt.Errorf("fake: %w", logstore.ErrNotFound)
	}
	return f.canonical[position], nil
}

func toLogstore(h verify.Hash) logstore.Hash {
	var out logstore.Hash
	copy(out[:], h[:])
	return out
}

func toLogstoreAll(hs []verify.Hash) []logstore.Hash {
	out := make([]logstore.Hash, len(hs))
	for i, h := range hs {
		out[i] = toLogstore(h)
	}
	return out
}

func splitPoint(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves []verify.Hash) verify.Hash {
	switch len(leaves) {
	case 0:
		return verify.HashEmpty()
	case 1:
		return leaves[0]
	default:
		k := splitPoint(uint64(len(leaves)))
		return verify.HashChildren(mth(leaves[:k]), mth(leaves[k:]))
	}
}

func path(leaves []verify.Hash, index uint64) []verify.Hash {
	if len(leaves) == 1 {
		return nil
	}
	k := splitPoint(uint64(len(leaves)))
	if index < k {
		return append(path(leaves[:k], index), mth(leaves[k:]))
	}
	return append(path(leaves[k:], index-k), mth(leaves[:k]))
}

func fakeServer(t *testing.T, entries int) (*httptest.Server, *fakeStore) {
	t.Helper()
	store := &fakeStore{}
	for i := 0; i < entries; i++ {
		if _, err := store.Append([]byte(fmt.Sprintf("entry-%d", i))); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	srv := httptest.NewServer(service.New(store, quietLogger()).Routes())
	t.Cleanup(srv.Close)
	return srv, store
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func postJSON(t *testing.T, url, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestAppendRejectsMalformedRequests(t *testing.T) {
	srv, _ := fakeServer(t, 0)

	cases := []struct {
		name, body string
		want       int
	}{
		{"not json", `{`, http.StatusBadRequest},
		{"payload not base64", `{"payload":"!!!!"}`, http.StatusBadRequest},
		{"unknown field", `{"payload":"","extra":1}`, http.StatusBadRequest},
		{"empty payload is legal", `{"payload":""}`, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := postJSON(t, srv.URL+"/append", tc.body)
			if code != tc.want {
				t.Errorf("status %d, want %d (body %s)", code, tc.want, body)
			}
		})
	}
}

func TestAppendResponseDescribesTheTreeItCreated(t *testing.T) {
	srv, _ := fakeServer(t, 0)
	for i := 0; i < 3; i++ {
		code, body := postJSON(t, srv.URL+"/append",
			fmt.Sprintf(`{"payload":%q}`, base64.StdEncoding.EncodeToString([]byte("x"))))
		if code != http.StatusCreated {
			t.Fatalf("status %d: %s", code, body)
		}
		var r service.AppendResponse
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.Position != uint64(i) {
			t.Errorf("position %d, want %d", r.Position, i)
		}
		// Size must be position+1, and the root must be the root at that
		// size — not the current root, which may have moved.
		if r.Size != r.Position+1 {
			t.Errorf("size %d with position %d", r.Size, r.Position)
		}
		if _, err := verify.ParseHash(r.Root); err != nil {
			t.Errorf("root is not a hash: %v", err)
		}
	}
}

func TestRootEndpoint(t *testing.T) {
	srv, _ := fakeServer(t, 10)

	code, body := get(t, srv.URL+"/root")
	if code != http.StatusOK {
		t.Fatalf("current root: status %d", code)
	}
	var r service.RootResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Size != 10 {
		t.Errorf("size %d, want 10", r.Size)
	}

	// A historical root.
	code, body = get(t, srv.URL+"/root?size=4")
	if code != http.StatusOK {
		t.Fatalf("historical root: status %d: %s", code, body)
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Size != 4 {
		t.Errorf("size %d, want 4", r.Size)
	}

	// The empty root is a real, requestable value.
	code, body = get(t, srv.URL+"/root?size=0")
	if code != http.StatusOK {
		t.Fatalf("size 0: status %d: %s", code, body)
	}
	_ = json.Unmarshal(body, &r)
	if r.Root != verify.HashEmpty().String() {
		t.Errorf("root at size 0 = %s, want the empty root", r.Root)
	}
}

func TestInvalidParametersAreRejected(t *testing.T) {
	srv, _ := fakeServer(t, 10)

	cases := []struct {
		name, path string
		want       int
	}{
		{"root size negative", "/root?size=-1", http.StatusBadRequest},
		{"root size not a number", "/root?size=abc", http.StatusBadRequest},
		{"root size too large", "/root?size=999", http.StatusNotFound},
		{"entry missing position", "/entry", http.StatusBadRequest},
		{"entry position negative", "/entry?position=-3", http.StatusBadRequest},
		{"entry past the end", "/entry?position=50", http.StatusNotFound},
		{"inclusion missing position", "/proof/inclusion", http.StatusBadRequest},
		{"inclusion bad tree size", "/proof/inclusion?position=0&tree_size=x", http.StatusBadRequest},
		{"inclusion tree too large", "/proof/inclusion?position=0&tree_size=999", http.StatusNotFound},
		{"inclusion index outside tree", "/proof/inclusion?position=9&tree_size=4", http.StatusBadRequest},
		{"consistency missing first", "/proof/consistency?second=5", http.StatusBadRequest},
		{"consistency reversed", "/proof/consistency?first=8&second=3", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := get(t, srv.URL+tc.path)
			if code != tc.want {
				t.Errorf("status %d, want %d (body %s)", code, tc.want, body)
			}
		})
	}
}

func TestInclusionTreeSizeDefaultsToCurrent(t *testing.T) {
	// A convenience for interactive use. The auditor always passes the size
	// explicitly, but the default must still be correct.
	srv, _ := fakeServer(t, 7)
	code, body := get(t, srv.URL+"/proof/inclusion?position=2")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var r service.InclusionResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TreeSize != 7 {
		t.Errorf("tree_size %d, want 7", r.TreeSize)
	}
	if r.LeafIndex != 2 {
		t.Errorf("leaf_index %d, want 2", r.LeafIndex)
	}
}

func TestEmptyProofSerialisesAsAnArrayNotNull(t *testing.T) {
	// A JSON `null` invites a client to treat an empty consistency proof as
	// absent rather than as the meaningful value it is.
	srv, _ := fakeServer(t, 4)
	code, body := get(t, srv.URL+"/proof/consistency?first=0&second=4")
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if !strings.Contains(string(body), `"proof":[]`) {
		t.Errorf("empty proof did not serialise as []: %s", body)
	}
}

func TestCorruptionIsReportedWithoutDetail(t *testing.T) {
	// A log that has been tampered with should not narrate the specifics to
	// whoever is probing it; the detail goes to the operator's log.
	srv, store := fakeServer(t, 5)
	store.fail = fmt.Errorf("entry 3 at byte 120 is corrupt: %w", logstore.ErrCorrupt)

	code, body := get(t, srv.URL+"/entry?position=1")
	if code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", code)
	}
	if strings.Contains(string(body), "byte 120") {
		t.Errorf("the response leaked corruption detail: %s", body)
	}
}

func TestClosedLogReportsUnavailable(t *testing.T) {
	srv, store := fakeServer(t, 5)
	store.fail = logstore.ErrClosed

	code, _ := get(t, srv.URL+"/entry?position=1")
	if code != http.StatusServiceUnavailable {
		t.Errorf("status %d, want 503", code)
	}
}

func TestHealthReportsSizeAndRoot(t *testing.T) {
	srv, _ := fakeServer(t, 3)
	code, body := get(t, srv.URL+"/health")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	var r service.RootResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Size != 3 {
		t.Errorf("size %d, want 3", r.Size)
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	srv, _ := fakeServer(t, 1)
	resp, err := http.Get(srv.URL + "/append")
	if err != nil {
		t.Fatalf("GET /append: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /append: status %d, want 405", resp.StatusCode)
	}
}
