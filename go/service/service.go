// Package service is the HTTP surface of the log.
//
// The endpoints are shaped by one rule: a client must be able to verify
// everything it is told without asking the server for anything it has to
// trust. Concretely, that means three things the obvious API would get wrong:
//
//   - **Proofs are always issued against an explicit tree size**, never
//     "current". A proof against a moving target cannot be checked later,
//     and an auditor comparing two observations needs to name the sizes.
//
//   - **Entries are returned as canonical bytes**, not just the payload. The
//     verifier hashes exactly what the log hashed instead of reconstructing
//     the framing and hoping it matches.
//
//   - **The response to an append includes the new size and root**, so a
//     client can immediately ask for an inclusion proof at a size it has
//     seen rather than racing other writers to guess one.
package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/LegendaryPenguin/sentinel/logstore"
)

// Store is the subset of *logstore.Log the service needs.
//
// An interface so the handler tests can run without cgo and so a future
// replicated store can be substituted. It is not an abstraction over
// "any log" — the method set is exactly what the endpoints require.
type Store interface {
	Size() (uint64, error)
	Append(payload []byte) (logstore.Entry, error)
	Root() (logstore.Hash, error)
	RootAt(size uint64) (logstore.Hash, error)
	InclusionProof(index, size uint64) ([]logstore.Hash, error)
	ConsistencyProof(first, second uint64) ([]logstore.Hash, error)
	EntryCanonical(position uint64) ([]byte, error)
}

// Server wires a Store to HTTP routes.
type Server struct {
	store Store
	log   *slog.Logger
	// maxPayload bounds a single appended entry. A transparency log accepts
	// data from whoever is allowed to write to it, so an unbounded body is an
	// unbounded memory commitment.
	maxPayload int64
}

const defaultMaxPayload = 1 << 20

func New(store Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: store, log: logger, maxPayload: defaultMaxPayload}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /append", s.handleAppend)
	mux.HandleFunc("GET /root", s.handleRoot)
	mux.HandleFunc("GET /entry", s.handleEntry)
	mux.HandleFunc("GET /proof/inclusion", s.handleInclusion)
	mux.HandleFunc("GET /proof/consistency", s.handleConsistency)
	mux.HandleFunc("GET /health", s.handleHealth)
	return mux
}

// ---------------------------------------------------------------------------
// Wire types
//
// Hashes are hex and payloads are base64. Hex for hashes because that is how
// every transparency-log tool and every operator writes them, and roots get
// pasted into tickets and compared by eye. Base64 for payloads because they
// are arbitrary bytes and hex would double an already-large body.
// ---------------------------------------------------------------------------

type AppendRequest struct {
	// Payload is base64. A JSON string would force callers to hold
	// text-shaped data, and a transparency log's entries are usually
	// certificates, signatures, or other binary.
	Payload string `json:"payload"`
}

type AppendResponse struct {
	Position       uint64 `json:"position"`
	TimestampNanos uint64 `json:"timestamp_nanos"`
	// Size and Root describe the log *after* the append, so the caller can
	// request an inclusion proof at a size it has actually observed.
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

type RootResponse struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

type EntryResponse struct {
	Position       uint64 `json:"position"`
	TimestampNanos uint64 `json:"timestamp_nanos"`
	Payload        string `json:"payload"`
	// Canonical is the exact byte string that was hashed into the leaf,
	// base64-encoded. A verifier hashes this and ignores the decoded fields
	// above, which are a convenience for humans reading the response.
	Canonical string `json:"canonical"`
}

type InclusionResponse struct {
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Root      string   `json:"root"`
	Proof     []string `json:"proof"`
	Canonical string   `json:"canonical"`
}

type ConsistencyResponse struct {
	FirstSize  uint64 `json:"first_size"`
	SecondSize uint64 `json:"second_size"`
	FirstRoot  string `json:"first_root"`
	SecondRoot string `json:"second_root"`
	// Proof is empty and must be for first == 0 or first == second. The
	// verifier requires emptiness there rather than tolerating nodes.
	Proof []string `json:"proof"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleAppend(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxPayload*2) // base64 overhead

	var req AppendRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("malformed request body: %w", err))
		return
	}

	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("payload is not valid base64: %w", err))
		return
	}
	if int64(len(payload)) > s.maxPayload {
		s.fail(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("payload is %d bytes, limit is %d", len(payload), s.maxPayload))
		return
	}

	entry, err := s.store.Append(payload)
	if err != nil {
		s.failInternal(w, "append", err)
		return
	}
	// The root is requested at `position + 1` rather than at the log's
	// current size. Those differ whenever another append lands in between,
	// and reporting the current size here would hand the client a root for a
	// tree that does not contain the entry it just wrote at the size it was
	// told. Deriving the size from the position makes the response describe
	// exactly the tree this append produced.
	root, err := s.store.RootAt(entry.Position + 1)
	if err != nil {
		s.failInternal(w, "root_at", err)
		return
	}

	s.respond(w, http.StatusCreated, AppendResponse{
		Position:       entry.Position,
		TimestampNanos: entry.TimestampNanos,
		Size:           entry.Position + 1,
		Root:           root.String(),
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	// No size parameter means the current root. An explicit size asks for a
	// historical one, which is what a verifier needs to check a consistency
	// proof it was given earlier.
	raw := r.URL.Query().Get("size")
	if raw == "" {
		size, err := s.store.Size()
		if err != nil {
			s.failInternal(w, "size", err)
			return
		}
		root, err := s.store.Root()
		if err != nil {
			s.failInternal(w, "root", err)
			return
		}
		s.respond(w, http.StatusOK, RootResponse{Size: size, Root: root.String()})
		return
	}

	size, err := parseUint(raw)
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("size: %w", err))
		return
	}
	root, err := s.store.RootAt(size)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no root for size %d", size))
		return
	}
	s.respond(w, http.StatusOK, RootResponse{Size: size, Root: root.String()})
}

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request) {
	position, err := parseUint(r.URL.Query().Get("position"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("position: %w", err))
		return
	}
	canonical, err := s.store.EntryCanonical(position)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no entry at position %d", position))
		return
	}

	// Decode for the human-readable fields. If this fails the log has handed
	// out bytes it cannot parse, which is a server fault and not a client
	// one — hence 500 rather than 400.
	entry, err := decodeCanonical(canonical)
	if err != nil {
		s.failInternal(w, "decode canonical", err)
		return
	}

	s.respond(w, http.StatusOK, EntryResponse{
		Position:       entry.position,
		TimestampNanos: entry.timestamp,
		Payload:        base64.StdEncoding.EncodeToString(entry.payload),
		Canonical:      base64.StdEncoding.EncodeToString(canonical),
	})
}

func (s *Server) handleInclusion(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	position, err := parseUint(q.Get("position"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("position: %w", err))
		return
	}

	// The tree size defaults to current only as a convenience for interactive
	// use. A verifier always passes it explicitly, because a proof whose size
	// was chosen by the server is a proof about an unknown tree.
	var size uint64
	if raw := q.Get("tree_size"); raw != "" {
		size, err = parseUint(raw)
		if err != nil {
			s.fail(w, http.StatusBadRequest, fmt.Errorf("tree_size: %w", err))
			return
		}
	} else {
		size, err = s.store.Size()
		if err != nil {
			s.failInternal(w, "size", err)
			return
		}
	}

	proof, err := s.store.InclusionProof(position, size)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no inclusion proof for position %d in a tree of %d", position, size))
		return
	}
	root, err := s.store.RootAt(size)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no root for size %d", size))
		return
	}
	canonical, err := s.store.EntryCanonical(position)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no entry at position %d", position))
		return
	}

	s.respond(w, http.StatusOK, InclusionResponse{
		LeafIndex: position,
		TreeSize:  size,
		Root:      root.String(),
		Proof:     hexAll(proof),
		Canonical: base64.StdEncoding.EncodeToString(canonical),
	})
}

func (s *Server) handleConsistency(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	first, err := parseUint(q.Get("first"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("first: %w", err))
		return
	}
	second, err := parseUint(q.Get("second"))
	if err != nil {
		s.fail(w, http.StatusBadRequest, fmt.Errorf("second: %w", err))
		return
	}

	proof, err := s.store.ConsistencyProof(first, second)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no consistency proof from %d to %d", first, second))
		return
	}
	firstRoot, err := s.store.RootAt(first)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no root for size %d", first))
		return
	}
	secondRoot, err := s.store.RootAt(second)
	if err != nil {
		s.failStore(w, err, fmt.Sprintf("no root for size %d", second))
		return
	}

	s.respond(w, http.StatusOK, ConsistencyResponse{
		FirstSize:  first,
		SecondSize: second,
		FirstRoot:  firstRoot.String(),
		SecondRoot: secondRoot.String(),
		Proof:      hexAll(proof),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	size, err := s.store.Size()
	if err != nil {
		s.failInternal(w, "size", err)
		return
	}
	root, err := s.store.Root()
	if err != nil {
		s.failInternal(w, "root", err)
		return
	}
	s.respond(w, http.StatusOK, RootResponse{Size: size, Root: root.String()})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hexAll(hashes []logstore.Hash) []string {
	// Non-nil even when empty: an empty consistency proof is a meaningful
	// value, and `null` in JSON invites a client to treat it as absent.
	out := make([]string, 0, len(hashes))
	for _, h := range hashes {
		out = append(out, h.String())
	}
	return out
}

func parseUint(raw string) (uint64, error) {
	if raw == "" {
		return 0, errors.New("missing")
	}
	// ParseUint rejects a leading '+' and '-', so negatives cannot wrap into
	// a huge size.
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a non-negative integer: %q", raw)
	}
	return v, nil
}

type decodedEntry struct {
	position  uint64
	timestamp uint64
	payload   []byte
}

// decodeCanonical parses the canonical framing for display purposes only.
//
// The service does not verify anything with this — verification is the
// client's job, by design. It exists so the JSON can show a human the
// position and payload without them having to base64-decode by hand.
func decodeCanonical(b []byte) (decodedEntry, error) {
	const header = 8 + 8 + 4
	if len(b) < header {
		return decodedEntry{}, fmt.Errorf("canonical entry is %d bytes, need %d", len(b), header)
	}
	be := func(p []byte) uint64 {
		var v uint64
		for _, c := range p {
			v = v<<8 | uint64(c)
		}
		return v
	}
	declared := int(be(b[16:20]))
	if declared != len(b)-header {
		return decodedEntry{}, fmt.Errorf("canonical entry declares %d payload bytes, has %d", declared, len(b)-header)
	}
	return decodedEntry{position: be(b[0:8]), timestamp: be(b[8:16]), payload: b[header:]}, nil
}

func (s *Server) respond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already written, so this can only be logged.
		s.log.Error("writing response", "error", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, code int, err error) {
	s.respond(w, code, ErrorResponse{Error: err.Error()})
}

// failStore maps a store error onto a status code.
//
// ErrNotFound and ErrProof are the client asking about a tree that does not
// exist or an entry outside it, so they are 404 and 400. Corruption is a 500
// and, deliberately, does not echo the detail: it is operator information,
// and a log that has been tampered with should not be narrating the specifics
// to whoever is probing it.
func (s *Server) failStore(w http.ResponseWriter, err error, notFoundMsg string) {
	switch {
	case errors.Is(err, logstore.ErrNotFound):
		s.fail(w, http.StatusNotFound, errors.New(notFoundMsg))
	case errors.Is(err, logstore.ErrProof):
		s.fail(w, http.StatusBadRequest, err)
	case errors.Is(err, logstore.ErrCorrupt):
		s.log.Error("log reports corruption", "error", err)
		s.fail(w, http.StatusInternalServerError, errors.New("log integrity failure"))
	case errors.Is(err, logstore.ErrClosed):
		s.fail(w, http.StatusServiceUnavailable, errors.New("log is shutting down"))
	default:
		s.failInternal(w, "store", err)
	}
}

func (s *Server) failInternal(w http.ResponseWriter, op string, err error) {
	s.log.Error("internal error", "op", op, "error", err)
	s.fail(w, http.StatusInternalServerError, errors.New("internal error"))
}

// ListenAndServe runs the server with timeouts set.
//
// The defaults in net/http are no timeouts at all, which turns a slow client
// into a held connection indefinitely.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}
