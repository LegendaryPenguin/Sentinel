/*
 * sentinel.h — the C ABI exported by sentinel-core.
 *
 * Hand-written rather than generated. cbindgen would produce most of this,
 * but the header is the contract between two languages and I would rather it
 * be a file someone can read and review than a build artifact that changes
 * shape when a tool is upgraded.
 *
 * Calling conventions, which hold for every function here:
 *
 *   - Status codes are returned; zero is success. Nothing is signalled by
 *     errno, and nothing throws.
 *   - On a non-zero status, sentinel_last_error() returns a message for the
 *     most recent failing call *on the calling thread*. It is valid until the
 *     next call on that thread, so copy it before doing anything else.
 *   - Output buffers are allocated by the caller. The library never hands
 *     back memory the caller has to free, which removes the question of whose
 *     allocator owns what.
 *   - A NULL handle is reported as SENTINEL_ERR_BAD_ARGUMENT rather than
 *     crashing, and sentinel_close(NULL) is a no-op, so a Go `defer` on a
 *     failed open path is safe.
 *   - Rust panics do not cross this boundary; they surface as
 *     SENTINEL_ERR_PANIC.
 */

#ifndef SENTINEL_H
#define SENTINEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SENTINEL_OK 0
#define SENTINEL_ERR_IO (-1)
#define SENTINEL_ERR_CORRUPT (-2)
#define SENTINEL_ERR_BAD_ARGUMENT (-3)
#define SENTINEL_ERR_NOT_FOUND (-4)
#define SENTINEL_ERR_BUFFER_TOO_SMALL (-5)
#define SENTINEL_ERR_PROOF (-6)
#define SENTINEL_ERR_PANIC (-7)

/* Length of every hash this library produces or accepts. */
#define SENTINEL_HASH_LEN 32

/*
 * Upper bound on proof length, in nodes. 64 levels spans a tree of 2^64
 * leaves and a consistency proof adds at most one node; 128 is deliberate
 * slack so a caller compiled against this constant cannot be overflowed by a
 * later change. A caller may therefore size proof buffers statically at
 * SENTINEL_MAX_PROOF_NODES * SENTINEL_HASH_LEN bytes and never ask how long a
 * proof will be before requesting it — which also avoids racing a log that is
 * growing between the two calls.
 */
#define SENTINEL_MAX_PROOF_NODES 128

/* Opaque. Created by sentinel_open, destroyed by sentinel_close. */
typedef struct SentinelLog SentinelLog;

/*
 * Message for the most recent failing call on this thread. Never NULL; the
 * empty string means no error has been recorded.
 */
const char *sentinel_last_error(void);

/*
 * Opens or creates the log at `path`, replaying it to rebuild the Merkle tree.
 *
 * sync_every != 0 selects fsync-before-return on every append. Zero leaves
 * durability to the OS and is for benchmarks and tests only.
 *
 * out_entries_loaded receives the number of entries recovered.
 * out_tail_discarded receives the number of bytes dropped from an incomplete
 * trailing record — non-zero means the previous process died mid-append.
 * Either may be NULL.
 *
 * Returns NULL on failure; see sentinel_last_error().
 */
SentinelLog *sentinel_open(const char *path, int sync_every,
                           uint64_t *out_entries_loaded,
                           uint64_t *out_tail_discarded);

/* Releases a handle. NULL is accepted and ignored. */
void sentinel_close(SentinelLog *handle);

/* Number of entries currently in the log. */
int32_t sentinel_size(const SentinelLog *handle, uint64_t *out);

/*
 * Appends `payload_len` bytes. `payload` may be NULL when `payload_len` is 0.
 *
 * The position and timestamp are assigned by the log, not the caller: a
 * client that chose its own position could overwrite an entry, and one that
 * chose its own timestamp could backdate a record the log attests to having
 * seen. Both out-parameters may be NULL.
 */
int32_t sentinel_append(SentinelLog *handle, const uint8_t *payload,
                        size_t payload_len, uint64_t *out_position,
                        uint64_t *out_timestamp);

/* Current root. `out` must have room for SENTINEL_HASH_LEN bytes. */
int32_t sentinel_root(const SentinelLog *handle, uint8_t *out);

/*
 * The root the log would have published at exactly `size` entries.
 *
 * Needed because a consistency proof relates two roots, and a verifier that
 * cannot obtain the older one has nothing to check against. Returns
 * SENTINEL_ERR_NOT_FOUND if `size` exceeds the current length.
 */
int32_t sentinel_root_at(const SentinelLog *handle, uint64_t size,
                         uint8_t *out);

/*
 * Inclusion proof for `index` within a tree of `size` entries.
 *
 * Writes *out_count * SENTINEL_HASH_LEN bytes into `out`, ordered leaf-first:
 * the sibling nearest the leaf comes first.
 */
int32_t sentinel_inclusion_proof(const SentinelLog *handle, uint64_t index,
                                 uint64_t size, uint8_t *out, size_t out_cap,
                                 size_t *out_count);

/*
 * Consistency proof showing the tree at `second` entries is an append-only
 * extension of the tree at `first`.
 *
 * An empty proof (*out_count == 0) is correct and expected when first == 0 or
 * first == second; a verifier must require emptiness in those cases rather
 * than merely tolerate it.
 */
int32_t sentinel_consistency_proof(const SentinelLog *handle, uint64_t first,
                                   uint64_t second, uint8_t *out,
                                   size_t out_cap, size_t *out_count);

/*
 * Writes the entry's canonical bytes — the exact bytes hashed into the leaf.
 *
 * Canonical rather than payload-only so a verifier's job is "hash these bytes
 * and check the proof" instead of "reimplement the producer's encoder
 * byte-for-byte and hope". *out_len is set to the required length even when
 * the status is SENTINEL_ERR_BUFFER_TOO_SMALL, so a caller may probe with
 * out_cap 0.
 */
int32_t sentinel_entry_canonical(const SentinelLog *handle, uint64_t position,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/*
 * Re-reads the file from byte zero, rebuilds the tree, and compares roots.
 *
 * This is the log checking itself, which is strictly weaker than an
 * independent verifier checking it — same code, same assumptions, so a
 * systematic error cancels. It catches in-memory state drifting from the
 * bytes on disk, which is the failure it is aimed at.
 */
int32_t sentinel_verify_integrity(const SentinelLog *handle, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SENTINEL_H */
