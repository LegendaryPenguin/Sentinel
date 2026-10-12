// Package audit is a client that does not trust the server it talks to.
//
// It fetches roots, entries and proofs over HTTP and checks every one of them
// with package verify before returning anything. No method here returns a
// value that has not been verified, which is a deliberate API choice: an
// auditor library with a `GetRoot` that returns an unchecked root invites a
// caller to use the unchecked one.
//
// Like verify, this package never imports logstore. An auditor runs on a
// machine that has never seen sentinel-core and cannot link it, so the
// dependency would make the tool unbuildable exactly where it is needed. The
// independence test in package verify covers verify; this package's own
// constraint is enforced by the same rule in audit_independence_test.go.
package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/LegendaryPenguin/sentinel/verify"
)

// Client talks to one Sentinel server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		// A default timeout rather than none. An auditor polling a log that
		// has stopped responding should fail, not hang until someone notices.
		HTTP: &http.Client{Timeout: 30 * time.Second},
	}
}

// SignedRoot is a size and the root at that size.
//
// Named "signed" aspirationally and honestly: there is no signature. The log
// has no key, so a client cannot distinguish the real server from a
// man-in-the-middle serving a self-consistent fake history. That gap is
// recorded in the README under what this project does not claim, and it is
// the single largest difference between this and a deployable transparency
// log.
type SignedRoot struct {
	Size uint64
	Root verify.Hash
}

type rootJSON struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

type entryJSON struct {
	Position       uint64 `json:"position"`
	TimestampNanos uint64 `json:"timestamp_nanos"`
	Payload        string `json:"payload"`
	Canonical      string `json:"canonical"`
}

type inclusionJSON struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Root      string   `json:"root"`
	Proof     []string `json:"proof"`
	Canonical string   `json:"canonical"`
}

type consistencyJSON struct {
	FirstSize  uint64   `json:"first_size"`
	SecondSize uint64   `json:"second_size"`
	FirstRoot  string   `json:"first_root"`
	SecondRoot string   `json:"second_root"`
	Proof      []string `json:"proof"`
}

type errorJSON struct {
	Error string `json:"error"`
}

// ErrServerMisbehaved means the response was well-formed but inconsistent
// with what was asked for — the server answered a different question.
//
// Separate from a verification failure on purpose. A proof that does not
// verify might be a buggy client; a response whose leaf_index differs from
// the requested position is the server rewriting the question, and an
// operator should read those differently.
var ErrServerMisbehaved = errors.New("audit: server response does not match the request")

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("audit: build request: %w", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("audit: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	// Bound the body. An auditor pointed at a hostile endpoint should not be
	// a memory exhaustion target.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("audit: read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e errorJSON
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return fmt.Errorf("audit: GET %s: %s (status %d)", path, e.Error, resp.StatusCode)
		}
		return fmt.Errorf("audit: GET %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("audit: decode %s: %w", path, err)
	}
	return nil
}

// Root fetches the current root.
func (c *Client) Root(ctx context.Context) (SignedRoot, error) {
	var r rootJSON
	if err := c.get(ctx, "/root", nil, &r); err != nil {
		return SignedRoot{}, err
	}
	h, err := verify.ParseHash(r.Root)
	if err != nil {
		return SignedRoot{}, err
	}
	return SignedRoot{Size: r.Size, Root: h}, nil
}

// RootAt fetches the root the log published at exactly size entries.
func (c *Client) RootAt(ctx context.Context, size uint64) (SignedRoot, error) {
	var r rootJSON
	q := url.Values{"size": {strconv.FormatUint(size, 10)}}
	if err := c.get(ctx, "/root", q, &r); err != nil {
		return SignedRoot{}, err
	}
	if r.Size != size {
		return SignedRoot{}, fmt.Errorf("%w: asked for size %d, got %d", ErrServerMisbehaved, size, r.Size)
	}
	h, err := verify.ParseHash(r.Root)
	if err != nil {
		return SignedRoot{}, err
	}
	return SignedRoot{Size: size, Root: h}, nil
}

// Append submits a payload and returns the position it landed at.
//
// Does not verify anything by itself — there is nothing to verify until a
// root is fetched. Callers that need the entry proven should follow with
// VerifyInclusion at the returned size.
func (c *Client) Append(ctx context.Context, payload []byte) (position, size uint64, err error) {
	body, err := json.Marshal(map[string]string{
		"payload": base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("audit: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/append", bytes.NewReader(body))
	if err != nil {
		return 0, 0, fmt.Errorf("audit: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("audit: POST /append: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, 0, fmt.Errorf("audit: read /append: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		var e errorJSON
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return 0, 0, fmt.Errorf("audit: POST /append: %s (status %d)", e.Error, resp.StatusCode)
		}
		return 0, 0, fmt.Errorf("audit: POST /append: status %d", resp.StatusCode)
	}

	var r struct {
		Position uint64 `json:"position"`
		Size     uint64 `json:"size"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return 0, 0, fmt.Errorf("audit: decode /append: %w", err)
	}
	if r.Size != r.Position+1 {
		return 0, 0, fmt.Errorf("%w: position %d with size %d", ErrServerMisbehaved, r.Position, r.Size)
	}
	return r.Position, r.Size, nil
}

// VerifyInclusion fetches and checks the proof that the entry at position is
// in the tree of treeSize entries, returning the verified entry.
//
// Checks performed, in order, because each would otherwise let a different
// lie through:
//
//  1. The response describes the request that was made. A server free to
//     answer about a different index or size can always produce a valid
//     proof — for some other entry.
//  2. The canonical bytes decode, and the position inside them matches the
//     one requested. The leaf commits to its own position, so a server
//     handing back entry 7's bytes for a request about entry 3 is caught
//     here rather than by the proof.
//  3. Re-encoding the decoded entry reproduces the canonical bytes exactly.
//     Without this a server could append padding to the real bytes; the
//     padded version hashes to a different leaf, but only if we hash what we
//     were given rather than what we parsed.
//  4. The proof verifies against the root.
func (c *Client) VerifyInclusion(ctx context.Context, position, treeSize uint64, root verify.Hash) (verify.Entry, error) {
	var r inclusionJSON
	q := url.Values{
		"position":  {strconv.FormatUint(position, 10)},
		"tree_size": {strconv.FormatUint(treeSize, 10)},
	}
	if err := c.get(ctx, "/proof/inclusion", q, &r); err != nil {
		return verify.Entry{}, err
	}

	if r.LeafIndex != position || r.TreeSize != treeSize {
		return verify.Entry{}, fmt.Errorf("%w: asked for index %d size %d, got index %d size %d",
			ErrServerMisbehaved, position, treeSize, r.LeafIndex, r.TreeSize)
	}

	servedRoot, err := verify.ParseHash(r.Root)
	if err != nil {
		return verify.Entry{}, err
	}
	// The caller supplies the root it is auditing against; the server's own
	// claim is only accepted if it agrees. Trusting r.Root would make the
	// whole check circular.
	if servedRoot != root {
		return verify.Entry{}, fmt.Errorf("%w: server root %s, auditing against %s",
			ErrServerMisbehaved, servedRoot, root)
	}

	canonical, err := base64.StdEncoding.DecodeString(r.Canonical)
	if err != nil {
		return verify.Entry{}, fmt.Errorf("audit: canonical bytes are not base64: %w", err)
	}
	entry, err := verify.ParseCanonical(canonical)
	if err != nil {
		return verify.Entry{}, fmt.Errorf("audit: position %d: %w", position, err)
	}
	if entry.Position != position {
		return verify.Entry{}, fmt.Errorf("%w: entry bytes carry position %d, requested %d",
			ErrServerMisbehaved, entry.Position, position)
	}
	if !bytes.Equal(entry.Canonical(), canonical) {
		return verify.Entry{}, fmt.Errorf("%w: canonical bytes are not the canonical encoding of their own contents",
			ErrServerMisbehaved)
	}

	proof, err := parseProof(r.Proof)
	if err != nil {
		return verify.Entry{}, err
	}
	if err := verify.Inclusion(position, treeSize, verify.HashLeaf(canonical), proof, root); err != nil {
		return verify.Entry{}, err
	}
	return entry, nil
}

// VerifyConsistency fetches and checks the proof that the tree at second
// extends the tree at first.
//
// The caller passes the roots it already holds. A consistency check where the
// server supplies both roots proves nothing at all — it is the auditor's
// *saved* earlier root that gives the check its meaning.
func (c *Client) VerifyConsistency(ctx context.Context, first, second uint64, firstRoot, secondRoot verify.Hash) error {
	var r consistencyJSON
	q := url.Values{
		"first":  {strconv.FormatUint(first, 10)},
		"second": {strconv.FormatUint(second, 10)},
	}
	if err := c.get(ctx, "/proof/consistency", q, &r); err != nil {
		return err
	}
	if r.FirstSize != first || r.SecondSize != second {
		return fmt.Errorf("%w: asked for %d -> %d, got %d -> %d",
			ErrServerMisbehaved, first, second, r.FirstSize, r.SecondSize)
	}

	servedFirst, err := verify.ParseHash(r.FirstRoot)
	if err != nil {
		return err
	}
	servedSecond, err := verify.ParseHash(r.SecondRoot)
	if err != nil {
		return err
	}
	if servedFirst != firstRoot {
		return fmt.Errorf("%w: server claims root %s at size %d, auditor holds %s — "+
			"this is what a rewritten history looks like",
			ErrServerMisbehaved, servedFirst, first, firstRoot)
	}
	if servedSecond != secondRoot {
		return fmt.Errorf("%w: server claims root %s at size %d, auditor holds %s",
			ErrServerMisbehaved, servedSecond, second, secondRoot)
	}

	proof, err := parseProof(r.Proof)
	if err != nil {
		return err
	}
	return verify.Consistency(first, second, firstRoot, secondRoot, proof)
}

func parseProof(hexes []string) ([]verify.Hash, error) {
	out := make([]verify.Hash, 0, len(hexes))
	for i, s := range hexes {
		h, err := verify.ParseHash(s)
		if err != nil {
			return nil, fmt.Errorf("audit: proof node %d: %w", i, err)
		}
		out = append(out, h)
	}
	return out, nil
}

// AuditReport is the outcome of a full sweep.
type AuditReport struct {
	Size             uint64
	Root             verify.Hash
	EntriesVerified  uint64
	ConsistencyPairs uint64
}

// AuditAll fetches the current root and verifies every entry's inclusion
// against it, plus a chain of consistency proofs.
//
// O(n) proof fetches, which is the honest cost of auditing a log you have
// never seen before: there is no shortcut that lets a first-time auditor
// trust a prefix. An auditor that has run before only needs one consistency
// proof from its saved root, which is what Monitor does.
func (c *Client) AuditAll(ctx context.Context) (AuditReport, error) {
	current, err := c.Root(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	report := AuditReport{Size: current.Size, Root: current.Root}

	for i := uint64(0); i < current.Size; i++ {
		if _, err := c.VerifyInclusion(ctx, i, current.Size, current.Root); err != nil {
			return report, fmt.Errorf("entry %d of %d: %w", i, current.Size, err)
		}
		report.EntriesVerified++
	}

	// Walk the consistency chain over a sample of prefix sizes. Every pair
	// would be O(n^2) fetches; the sample covers 0, 1, the powers of two, and
	// the final size, which is where the proof shapes differ.
	for _, size := range sampleSizes(current.Size) {
		earlier, err := c.RootAt(ctx, size)
		if err != nil {
			return report, fmt.Errorf("root at %d: %w", size, err)
		}
		err = c.VerifyConsistency(ctx, size, current.Size, earlier.Root, current.Root)
		if err != nil {
			return report, fmt.Errorf("consistency %d -> %d: %w", size, current.Size, err)
		}
		report.ConsistencyPairs++
	}
	return report, nil
}

// Monitor is the operation a repeat auditor actually runs: prove that the log
// it is looking at now extends the log it saw last time.
//
// This is the whole value proposition of a transparency log in one call. It
// needs exactly one proof regardless of how much the log grew, and it is the
// only check that can detect a history rewrite — an inclusion proof against
// the current root cannot, because a rewritten log is internally consistent.
func (c *Client) Monitor(ctx context.Context, saved SignedRoot) (SignedRoot, error) {
	current, err := c.Root(ctx)
	if err != nil {
		return SignedRoot{}, err
	}
	if current.Size < saved.Size {
		return SignedRoot{}, fmt.Errorf("%w: log shrank from %d to %d entries",
			ErrServerMisbehaved, saved.Size, current.Size)
	}
	err = c.VerifyConsistency(ctx, saved.Size, current.Size, saved.Root, current.Root)
	if err != nil {
		return SignedRoot{}, err
	}
	return current, nil
}

func sampleSizes(n uint64) []uint64 {
	seen := map[uint64]bool{}
	var out []uint64
	add := func(v uint64) {
		if v <= n && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(0)
	add(1)
	for p := uint64(2); p <= n; p *= 2 {
		add(p)
		add(p + 1)
	}
	add(n / 2)
	add(n)
	return out
}
