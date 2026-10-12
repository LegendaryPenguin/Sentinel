// Package logstore is the cgo bridge to sentinel-core.
//
// It is the only package in the repository that links Rust, and it exists to
// keep that fact contained: everything above it sees ordinary Go types and
// errors. Nothing here implements any part of the log or the tree — if a
// function in this file does arithmetic on a hash, something has gone wrong.
//
// Two things this package is responsible for that the Rust side cannot be:
//
//   - **Serialising access.** `sentinel-core`'s `Log` is a plain Rust struct
//     with no internal locking, so concurrent calls would race. The RWMutex
//     below mirrors Rust's own borrow rules across the boundary: `append`
//     needs `&mut self` and takes the write lock; everything else needs
//     `&self` and takes the read lock. Getting this wrong produces a data
//     race that no amount of Go-side testing would reliably surface.
//
//   - **Copying error strings immediately.** `sentinel_last_error` returns a
//     thread-local buffer valid only until the next call on that thread, and
//     a goroutine can be rescheduled onto another OS thread between calls.
//     Every error is converted to a Go string before anything else happens.
package logstore

/*
#cgo CFLAGS: -I${SRCDIR}/../../sentinel-core/include
#cgo LDFLAGS: -L${SRCDIR}/../../sentinel-core/target/release -lsentinel_core

#include <stdlib.h>
#include "sentinel.h"
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// HashLen must agree with SENTINEL_HASH_LEN. Asserted at init rather than
// trusted, because a mismatch would silently truncate every root.
const HashLen = 32

// Hash is a tree hash.
//
// Deliberately a distinct type from verify.Hash rather than a shared one. The
// real boundary between the server and an auditor is the hex on the wire, and
// giving the two sides separate types means a change to one cannot quietly
// propagate into the other through a shared definition.
type Hash [HashLen]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// maxProofNodes must agree with SENTINEL_MAX_PROOF_NODES.
const maxProofNodes = 128

func init() {
	if C.SENTINEL_HASH_LEN != HashLen {
		panic("logstore: SENTINEL_HASH_LEN disagrees with HashLen")
	}
	if C.SENTINEL_MAX_PROOF_NODES != maxProofNodes {
		panic("logstore: SENTINEL_MAX_PROOF_NODES disagrees with maxProofNodes")
	}
}

// Sentinel errors mapped from the C status codes, so callers can branch on
// the kind of failure without string matching.
var (
	ErrNotFound   = errors.New("logstore: not found")
	ErrCorrupt    = errors.New("logstore: log is corrupt")
	ErrBadArgs    = errors.New("logstore: bad argument")
	ErrProof      = errors.New("logstore: proof unavailable")
	ErrCorePanic  = errors.New("logstore: panic inside sentinel-core")
	ErrBufferSize = errors.New("logstore: output buffer too small")
)

// status converts a C status plus the thread-local message into a Go error.
//
// Called while still on the same OS thread as the failing call, which is why
// every caller invokes it immediately rather than deferring.
func status(code C.int32_t, op string) error {
	if code == C.SENTINEL_OK {
		return nil
	}
	msg := C.GoString(C.sentinel_last_error())
	var base error
	switch code {
	case C.SENTINEL_ERR_NOT_FOUND:
		base = ErrNotFound
	case C.SENTINEL_ERR_CORRUPT:
		base = ErrCorrupt
	case C.SENTINEL_ERR_BAD_ARGUMENT:
		base = ErrBadArgs
	case C.SENTINEL_ERR_PROOF:
		base = ErrProof
	case C.SENTINEL_ERR_PANIC:
		base = ErrCorePanic
	case C.SENTINEL_ERR_BUFFER_TOO_SMALL:
		base = ErrBufferSize
	default:
		base = errors.New("logstore: io error")
	}
	if msg == "" {
		return fmt.Errorf("%s: %w (status %d)", op, base, int(code))
	}
	return fmt.Errorf("%s: %w: %s", op, base, msg)
}

// Recovery reports what Open found, so a caller can log it rather than having
// crash recovery be invisible.
type Recovery struct {
	EntriesLoaded uint64
	// TailBytesDiscarded is non-zero when the previous process died
	// mid-append. The entry was never acknowledged and no root ever contained
	// it, so discarding it is correct — but it is worth knowing it happened.
	TailBytesDiscarded uint64
}

// Log is a handle on an open Sentinel log.
type Log struct {
	mu     sync.RWMutex
	handle *C.SentinelLog
	path   string
}

// Open opens or creates the log at path, replaying it to rebuild the tree.
//
// syncEvery selects fsync-before-return on every append. Passing false is for
// benchmarks and tests; it is the difference between an acknowledged entry
// being durable and being probably durable, and there is no return value that
// can express the second one.
func Open(path string, syncEvery bool) (*Log, Recovery, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	var loaded, discarded C.uint64_t
	sync := C.int(0)
	if syncEvery {
		sync = C.int(1)
	}

	handle := C.sentinel_open(cPath, sync, &loaded, &discarded)
	if handle == nil {
		msg := C.GoString(C.sentinel_last_error())
		return nil, Recovery{}, fmt.Errorf("logstore: open %s: %s", path, msg)
	}

	l := &Log{handle: handle, path: path}
	// A finalizer is a backstop, not the plan: callers are expected to Close.
	// Without it a dropped handle leaks the Rust-side allocation and, more
	// importantly, holds the file open for the lifetime of the process.
	runtime.SetFinalizer(l, func(l *Log) { l.Close() })

	return l, Recovery{EntriesLoaded: uint64(loaded), TailBytesDiscarded: uint64(discarded)}, nil
}

// Close releases the handle. Safe to call more than once.
func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.handle != nil {
		C.sentinel_close(l.handle)
		l.handle = nil
		runtime.SetFinalizer(l, nil)
	}
}

// ErrClosed is returned by every method once Close has run. Returned rather
// than panicking because an HTTP handler racing a shutdown is a normal event,
// not a bug.
var ErrClosed = errors.New("logstore: log is closed")

func (l *Log) Path() string { return l.path }

// Size returns the number of entries.
func (l *Log) Size() (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return 0, ErrClosed
	}
	var out C.uint64_t
	if err := status(C.sentinel_size(l.handle, &out), "size"); err != nil {
		return 0, err
	}
	return uint64(out), nil
}

// Entry is an appended entry, with the position and timestamp the log
// assigned.
type Entry struct {
	Position       uint64
	TimestampNanos uint64
}

// Append adds payload to the log.
//
// Takes the write lock: the underlying Rust call needs `&mut self`, and two
// concurrent appends would both compute position from a stale length.
func (l *Log) Append(payload []byte) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.handle == nil {
		return Entry{}, ErrClosed
	}

	// An empty payload is legal. &payload[0] would panic on a zero-length
	// slice, so pass nil and let the C side synthesise an empty slice — the
	// header documents that length zero with a null pointer is accepted.
	var ptr *C.uint8_t
	if len(payload) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&payload[0]))
	}

	var pos, ts C.uint64_t
	code := C.sentinel_append(l.handle, ptr, C.size_t(len(payload)), &pos, &ts)
	if err := status(code, "append"); err != nil {
		return Entry{}, err
	}
	// Keep payload alive across the call. The Rust side copies into a Vec
	// before returning, but the compiler does not know that and the slice is
	// otherwise dead after &payload[0].
	runtime.KeepAlive(payload)

	return Entry{Position: uint64(pos), TimestampNanos: uint64(ts)}, nil
}

// Root returns the current root.
func (l *Log) Root() (Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return Hash{}, ErrClosed
	}
	var out Hash
	code := C.sentinel_root(l.handle, (*C.uint8_t)(unsafe.Pointer(&out[0])))
	if err := status(code, "root"); err != nil {
		return Hash{}, err
	}
	return out, nil
}

// RootAt returns the root the log published at exactly size entries.
func (l *Log) RootAt(size uint64) (Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return Hash{}, ErrClosed
	}
	var out Hash
	code := C.sentinel_root_at(l.handle, C.uint64_t(size), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	if err := status(code, fmt.Sprintf("root_at(%d)", size)); err != nil {
		return Hash{}, err
	}
	return out, nil
}

// InclusionProof returns the proof for index within a tree of size entries,
// ordered leaf-first.
func (l *Log) InclusionProof(index, size uint64) ([]Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return nil, ErrClosed
	}
	buf := make([]byte, maxProofNodes*HashLen)
	var count C.size_t
	code := C.sentinel_inclusion_proof(
		l.handle,
		C.uint64_t(index), C.uint64_t(size),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &count,
	)
	if err := status(code, fmt.Sprintf("inclusion_proof(%d, %d)", index, size)); err != nil {
		return nil, err
	}
	return splitHashes(buf, int(count)), nil
}

// ConsistencyProof returns the proof that the tree at second extends the tree
// at first.
//
// An empty result is correct when first is 0 or equal to second; callers must
// pass it through rather than treating it as a failure, and verifiers must
// require emptiness in those cases.
func (l *Log) ConsistencyProof(first, second uint64) ([]Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return nil, ErrClosed
	}
	buf := make([]byte, maxProofNodes*HashLen)
	var count C.size_t
	code := C.sentinel_consistency_proof(
		l.handle,
		C.uint64_t(first), C.uint64_t(second),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &count,
	)
	if err := status(code, fmt.Sprintf("consistency_proof(%d, %d)", first, second)); err != nil {
		return nil, err
	}
	return splitHashes(buf, int(count)), nil
}

func splitHashes(buf []byte, count int) []Hash {
	out := make([]Hash, count)
	for i := 0; i < count; i++ {
		copy(out[i][:], buf[i*HashLen:(i+1)*HashLen])
	}
	return out
}

// EntryCanonical returns the exact bytes that were hashed into the leaf at
// position.
//
// Canonical bytes rather than the payload because that is what a verifier
// needs: handing over the payload alone would require the verifier to
// reconstruct the producer's framing byte-for-byte, and any disagreement
// would look like tampering.
func (l *Log) EntryCanonical(position uint64) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return nil, ErrClosed
	}

	// Probe for the length with a zero-capacity buffer. The read lock is held
	// across both calls, so the entry cannot change underneath the second
	// one — a detail that matters because the probe-then-fetch pattern is
	// exactly where a growing log would otherwise race.
	var need C.size_t
	code := C.sentinel_entry_canonical(l.handle, C.uint64_t(position), nil, 0, &need)
	switch {
	case code == C.SENTINEL_ERR_BUFFER_TOO_SMALL:
		// Expected: the probe always reports the size this way.
	case code == C.SENTINEL_OK && need == 0:
		// A zero-length canonical encoding is impossible (the header alone is
		// 20 bytes), so treat it as a protocol violation rather than an entry.
		return nil, fmt.Errorf("entry_canonical(%d): core reported a zero-length entry", position)
	default:
		if err := status(code, fmt.Sprintf("entry_canonical(%d) probe", position)); err != nil {
			return nil, err
		}
	}

	buf := make([]byte, int(need))
	var got C.size_t
	code = C.sentinel_entry_canonical(
		l.handle, C.uint64_t(position),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &got,
	)
	if err := status(code, fmt.Sprintf("entry_canonical(%d)", position)); err != nil {
		return nil, err
	}
	return buf[:int(got)], nil
}

// VerifyIntegrity re-reads the file and rebuilds the tree inside the core,
// returning the number of entries replayed.
//
// Weaker than the Go verifier checking the server, and labelled as such in
// the API docs so nobody mistakes it for an audit: same code, same
// assumptions, so a systematic error cancels out. It catches in-memory state
// drifting from the bytes on disk.
func (l *Log) VerifyIntegrity() (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.handle == nil {
		return 0, ErrClosed
	}
	var out C.uint64_t
	if err := status(C.sentinel_verify_integrity(l.handle, &out), "verify_integrity"); err != nil {
		return 0, err
	}
	return uint64(out), nil
}
