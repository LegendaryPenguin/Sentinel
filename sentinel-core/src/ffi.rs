//! The C ABI the Go service links against.
//!
//! Three rules shape this file, all learned the tedious way:
//!
//!   1. **No Rust type crosses the boundary.** Handles are opaque pointers,
//!      buffers are caller-allocated, and every output is a plain integer or
//!      bytes. Nothing on the Go side needs to know Rust's layout.
//!   2. **No panic crosses the boundary.** Unwinding into C is undefined
//!      behaviour, so every entry point is wrapped in `catch_unwind` and a
//!      panic becomes `STATUS_PANIC` plus a message in the thread-local error
//!      slot. The tree's `assert!`s are reachable from here via bad
//!      arguments, so this is not theoretical.
//!   3. **Buffers are fixed-capacity, not negotiated.** A proof for a tree of
//!      2^64 entries is at most 64 nodes for inclusion and one more for
//!      consistency, so `MAX_PROOF_NODES` of 128 is permanently sufficient.
//!      That removes the two-call "ask the size, then fetch" dance and the
//!      race it implies when the log is growing between the two calls.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::hash::HASH_LEN;
use crate::log::{Log, SyncPolicy};

pub const STATUS_OK: i32 = 0;
pub const STATUS_IO: i32 = -1;
pub const STATUS_CORRUPT: i32 = -2;
pub const STATUS_BAD_ARGUMENT: i32 = -3;
pub const STATUS_NOT_FOUND: i32 = -4;
pub const STATUS_BUFFER_TOO_SMALL: i32 = -5;
pub const STATUS_PROOF: i32 = -6;
pub const STATUS_PANIC: i32 = -7;

/// Bounds every proof buffer. 64 levels covers a tree of 2^64 leaves; the
/// doubling is slack so a future scheme that adds nodes cannot overflow a
/// caller compiled against the old constant.
pub const MAX_PROOF_NODES: usize = 128;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_error(msg: impl Into<String>) {
    let msg = msg.into();
    // Interior NULs cannot be represented; replace rather than lose the
    // message, since this only ever runs on an error path.
    let c = CString::new(msg.replace('\0', "?")).unwrap_or_else(|_| CString::new("error").unwrap());
    LAST_ERROR.with(|slot| *slot.borrow_mut() = c);
}

fn clear_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = CString::new("").unwrap());
}

/// The message for the most recent failing call on this thread.
///
/// Valid until the next call on the same thread, which is the usual C
/// contract and is why the Go wrapper copies it into a Go string immediately.
#[no_mangle]
pub extern "C" fn sentinel_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Opaque to C. Boxed so the address is stable across Rust moves.
pub struct SentinelLog {
    inner: Log,
}

fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(status) => status,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic".to_string());
            set_error(format!("panic in sentinel-core: {msg}"));
            STATUS_PANIC
        }
    }
}

/// Opens the log at `path`. Returns null on failure, with the reason in
/// `sentinel_last_error`.
///
/// `sync_every` non-zero selects fsync-per-append.
///
/// # Safety
///
/// `path` must be a valid NUL-terminated C string. `out_entries_loaded`
/// and `out_tail_discarded` must each be either null or a writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_open(
    path: *const c_char,
    sync_every: c_int,
    out_entries_loaded: *mut u64,
    out_tail_discarded: *mut u64,
) -> *mut SentinelLog {
    let mut handle: *mut SentinelLog = ptr::null_mut();
    guard(|| {
        clear_error();
        if path.is_null() {
            set_error("path is null");
            return STATUS_BAD_ARGUMENT;
        }
        let path = match unsafe { CStr::from_ptr(path) }.to_str() {
            Ok(p) => p,
            Err(e) => {
                set_error(format!("path is not valid UTF-8: {e}"));
                return STATUS_BAD_ARGUMENT;
            }
        };
        let policy = if sync_every != 0 {
            SyncPolicy::EveryAppend
        } else {
            SyncPolicy::Never
        };
        match Log::open(path, policy) {
            Ok((log, recovery)) => {
                if !out_entries_loaded.is_null() {
                    unsafe { *out_entries_loaded = recovery.entries_loaded };
                }
                if !out_tail_discarded.is_null() {
                    unsafe { *out_tail_discarded = recovery.tail_bytes_discarded };
                }
                handle = Box::into_raw(Box::new(SentinelLog { inner: log }));
                STATUS_OK
            }
            Err(e) => {
                set_error(e.to_string());
                STATUS_IO
            }
        }
    });
    handle
}

/// Closes a handle from `sentinel_open`. Null is accepted and ignored.
///
/// # Safety
///
/// `handle` must be null, or a pointer returned by [`sentinel_open`] that
/// has not already been closed. The pointer must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn sentinel_close(handle: *mut SentinelLog) {
    if handle.is_null() {
        return;
    }
    guard(|| {
        unsafe { drop(Box::from_raw(handle)) };
        STATUS_OK
    });
}

macro_rules! log_ref {
    ($handle:expr) => {
        match unsafe { $handle.as_ref() } {
            Some(h) => h,
            None => {
                set_error("log handle is null");
                return STATUS_BAD_ARGUMENT;
            }
        }
    };
}

///
/// # Safety
///
/// `handle` must be null or a live handle from [`sentinel_open`]. `out`
/// must be null or a writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_size(handle: *const SentinelLog, out: *mut u64) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out.is_null() {
            set_error("out is null");
            return STATUS_BAD_ARGUMENT;
        }
        unsafe { *out = log.inner.len() };
        STATUS_OK
    })
}

///
/// # Safety
///
/// `handle` must be null or a live handle. `payload` must point to
/// `payload_len` readable bytes, or be null when `payload_len` is zero.
/// The out-parameters must each be null or a writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_append(
    handle: *mut SentinelLog,
    payload: *const u8,
    payload_len: usize,
    out_position: *mut u64,
    out_timestamp: *mut u64,
) -> i32 {
    guard(|| {
        clear_error();
        let log = match unsafe { handle.as_mut() } {
            Some(h) => h,
            None => {
                set_error("log handle is null");
                return STATUS_BAD_ARGUMENT;
            }
        };
        // A zero-length payload is legal, and `from_raw_parts` requires a
        // non-null, aligned pointer even for length zero — so synthesise an
        // empty slice rather than trusting the caller's null.
        let bytes: &[u8] = if payload_len == 0 {
            &[]
        } else if payload.is_null() {
            set_error("payload is null with non-zero length");
            return STATUS_BAD_ARGUMENT;
        } else {
            unsafe { std::slice::from_raw_parts(payload, payload_len) }
        };

        match log.inner.append(bytes) {
            Ok(entry) => {
                if !out_position.is_null() {
                    unsafe { *out_position = entry.position };
                }
                if !out_timestamp.is_null() {
                    unsafe { *out_timestamp = entry.timestamp_nanos };
                }
                STATUS_OK
            }
            Err(e) => {
                set_error(e.to_string());
                STATUS_IO
            }
        }
    })
}

///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be writable for
/// [`HASH_LEN`] bytes.
#[no_mangle]
pub unsafe extern "C" fn sentinel_root(handle: *const SentinelLog, out: *mut u8) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out.is_null() {
            set_error("out is null");
            return STATUS_BAD_ARGUMENT;
        }
        let root = log.inner.root();
        unsafe { ptr::copy_nonoverlapping(root.as_ptr(), out, HASH_LEN) };
        STATUS_OK
    })
}

///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be writable for
/// [`HASH_LEN`] bytes.
#[no_mangle]
pub unsafe extern "C" fn sentinel_root_at(
    handle: *const SentinelLog,
    size: u64,
    out: *mut u8,
) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out.is_null() {
            set_error("out is null");
            return STATUS_BAD_ARGUMENT;
        }
        match log.inner.root_at(size) {
            Some(root) => {
                unsafe { ptr::copy_nonoverlapping(root.as_ptr(), out, HASH_LEN) };
                STATUS_OK
            }
            None => {
                set_error(format!(
                    "no root for size {size}: log holds {}",
                    log.inner.len()
                ));
                STATUS_NOT_FOUND
            }
        }
    })
}

/// Writes `out_count * 32` bytes of proof nodes into `out`.
///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be writable for
/// `out_cap` bytes and `out_count` must be a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_inclusion_proof(
    handle: *const SentinelLog,
    index: u64,
    size: u64,
    out: *mut u8,
    out_cap: usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out.is_null() || out_count.is_null() {
            set_error("out or out_count is null");
            return STATUS_BAD_ARGUMENT;
        }
        if size > log.inner.len() {
            set_error(format!(
                "size {size} exceeds log length {}",
                log.inner.len()
            ));
            return STATUS_NOT_FOUND;
        }
        match log.inner.tree().inclusion_proof(index, size) {
            Ok(proof) => write_proof(&proof, out, out_cap, out_count),
            Err(e) => {
                set_error(e.to_string());
                STATUS_PROOF
            }
        }
    })
}

///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be writable for
/// `out_cap` bytes and `out_count` must be a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_consistency_proof(
    handle: *const SentinelLog,
    first: u64,
    second: u64,
    out: *mut u8,
    out_cap: usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out.is_null() || out_count.is_null() {
            set_error("out or out_count is null");
            return STATUS_BAD_ARGUMENT;
        }
        if second > log.inner.len() {
            set_error(format!(
                "size {second} exceeds log length {}",
                log.inner.len()
            ));
            return STATUS_NOT_FOUND;
        }
        match log.inner.tree().consistency_proof(first, second) {
            Ok(proof) => write_proof(&proof, out, out_cap, out_count),
            Err(e) => {
                set_error(e.to_string());
                STATUS_PROOF
            }
        }
    })
}

fn write_proof(
    proof: &[crate::hash::Hash],
    out: *mut u8,
    out_cap: usize,
    out_count: *mut usize,
) -> i32 {
    let needed = proof.len() * HASH_LEN;
    if out_cap < needed {
        set_error(format!(
            "buffer of {out_cap} bytes is too small for {needed}"
        ));
        return STATUS_BUFFER_TOO_SMALL;
    }
    for (i, node) in proof.iter().enumerate() {
        unsafe { ptr::copy_nonoverlapping(node.as_ptr(), out.add(i * HASH_LEN), HASH_LEN) };
    }
    unsafe { *out_count = proof.len() };
    STATUS_OK
}

/// Writes the entry's **canonical** bytes — the exact bytes that were hashed
/// into the leaf.
///
/// Canonical rather than payload-only on purpose. A verifier that receives
/// only the payload has to reconstruct position and timestamp framing to
/// rebuild the leaf, which means reimplementing this crate's encoder and
/// getting it byte-identical. Handing over the hashed bytes directly makes
/// the verifier's job "hash this and check the proof" and removes an entire
/// category of disagreement.
///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be writable for
/// `out_cap` bytes and `out_len` must be a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_entry_canonical(
    handle: *const SentinelLog,
    position: u64,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        if out_len.is_null() {
            set_error("out_len is null");
            return STATUS_BAD_ARGUMENT;
        }
        match log.inner.entry(position) {
            Ok(Some(entry)) => {
                let canonical = entry.canonical();
                unsafe { *out_len = canonical.len() };
                if out_cap < canonical.len() {
                    set_error(format!(
                        "buffer of {out_cap} bytes is too small for {}",
                        canonical.len()
                    ));
                    return STATUS_BUFFER_TOO_SMALL;
                }
                if out.is_null() {
                    set_error("out is null");
                    return STATUS_BAD_ARGUMENT;
                }
                unsafe { ptr::copy_nonoverlapping(canonical.as_ptr(), out, canonical.len()) };
                STATUS_OK
            }
            Ok(None) => {
                set_error(format!("no entry at position {position}"));
                STATUS_NOT_FOUND
            }
            Err(e) => {
                set_error(e.to_string());
                STATUS_CORRUPT
            }
        }
    })
}

///
/// # Safety
///
/// `handle` must be null or a live handle. `out` must be null or a
/// writable `u64`.
#[no_mangle]
pub unsafe extern "C" fn sentinel_verify_integrity(
    handle: *const SentinelLog,
    out: *mut u64,
) -> i32 {
    guard(|| {
        clear_error();
        let log = log_ref!(handle);
        match log.inner.verify_integrity() {
            Ok(n) => {
                if !out.is_null() {
                    unsafe { *out = n };
                }
                STATUS_OK
            }
            Err(e) => {
                set_error(e.to_string());
                STATUS_CORRUPT
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // Every call below is in an `unsafe` block because the entry points are
    // declared `unsafe fn`: they dereference caller-supplied pointers, and
    // saying so in the signature is more useful than silencing the lint. The
    // `unsafe` marker is Rust-side only — the exported symbol and the C ABI
    // cgo links against are unchanged.

    fn temp_path(tag: &str) -> CString {
        let mut p = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("sentinel-ffi-{tag}-{unique}.log"));
        CString::new(p.to_str().unwrap()).unwrap()
    }

    #[test]
    fn open_append_root_close() {
        let path = temp_path("basic");
        unsafe {
            let mut loaded = 0u64;
            let mut discarded = 0u64;
            let h = sentinel_open(path.as_ptr(), 0, &mut loaded, &mut discarded);
            assert!(!h.is_null());
            assert_eq!(loaded, 0);

            let mut pos = 0u64;
            let mut ts = 0u64;
            assert_eq!(
                sentinel_append(h, b"hello".as_ptr(), 5, &mut pos, &mut ts),
                STATUS_OK
            );
            assert_eq!(pos, 0);
            assert!(ts > 0);

            let mut size = 0u64;
            assert_eq!(sentinel_size(h, &mut size), STATUS_OK);
            assert_eq!(size, 1);

            let mut root = [0u8; HASH_LEN];
            assert_eq!(sentinel_root(h, root.as_mut_ptr()), STATUS_OK);
            assert_ne!(root, [0u8; HASH_LEN]);

            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn zero_length_payload_with_null_pointer_is_accepted() {
        // Go passes a nil pointer for an empty byte slice, so this is the
        // real calling convention and not a hypothetical.
        let path = temp_path("empty");
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            assert!(!h.is_null());
            let mut pos = 0u64;
            assert_eq!(
                sentinel_append(h, ptr::null(), 0, &mut pos, ptr::null_mut()),
                STATUS_OK
            );
            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn null_handle_is_rejected_rather_than_crashing() {
        unsafe {
            let mut size = 0u64;
            assert_eq!(sentinel_size(ptr::null(), &mut size), STATUS_BAD_ARGUMENT);
            let mut root = [0u8; HASH_LEN];
            assert_eq!(
                sentinel_root(ptr::null(), root.as_mut_ptr()),
                STATUS_BAD_ARGUMENT
            );
            // And close tolerates it, because Go's defer will call it on a
            // failed open path.
            sentinel_close(ptr::null_mut());
        }
    }

    #[test]
    fn a_panic_becomes_a_status_not_an_abort() {
        // `root_at` beyond the tree asserts inside the tree; reaching it
        // through the FFI must produce STATUS_NOT_FOUND from the explicit
        // check rather than unwinding. Proof requests past the end take the
        // same guarded path.
        let path = temp_path("panic");
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            let mut pos = 0u64;
            sentinel_append(h, b"x".as_ptr(), 1, &mut pos, ptr::null_mut());

            let mut root = [0u8; HASH_LEN];
            assert_eq!(sentinel_root_at(h, 99, root.as_mut_ptr()), STATUS_NOT_FOUND);

            let mut buf = [0u8; MAX_PROOF_NODES * HASH_LEN];
            let mut count = 0usize;
            assert_eq!(
                sentinel_inclusion_proof(h, 0, 99, buf.as_mut_ptr(), buf.len(), &mut count),
                STATUS_NOT_FOUND
            );
            // An out-of-range index inside a valid size is a proof error.
            assert_eq!(
                sentinel_inclusion_proof(h, 5, 1, buf.as_mut_ptr(), buf.len(), &mut count),
                STATUS_PROOF
            );
            assert!(!CStr::from_ptr(sentinel_last_error()).to_bytes().is_empty());

            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn undersized_proof_buffer_is_reported() {
        let path = temp_path("small-buf");
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            for i in 0..8u64 {
                let p = format!("entry-{i}");
                let mut pos = 0u64;
                sentinel_append(h, p.as_ptr(), p.len(), &mut pos, ptr::null_mut());
            }
            let mut tiny = [0u8; HASH_LEN]; // room for one node, need three
            let mut count = 0usize;
            assert_eq!(
                sentinel_inclusion_proof(h, 0, 8, tiny.as_mut_ptr(), tiny.len(), &mut count),
                STATUS_BUFFER_TOO_SMALL
            );
            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn canonical_bytes_round_trip_through_the_boundary() {
        let path = temp_path("canonical");
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            let mut pos = 0u64;
            sentinel_append(h, b"payload bytes".as_ptr(), 13, &mut pos, ptr::null_mut());

            let mut buf = [0u8; 256];
            let mut len = 0usize;
            assert_eq!(
                sentinel_entry_canonical(h, 0, buf.as_mut_ptr(), buf.len(), &mut len),
                STATUS_OK
            );
            let entry = crate::record::Entry::from_canonical(&buf[..len]).unwrap();
            assert_eq!(entry.payload, b"payload bytes");
            assert_eq!(entry.position, 0);

            // The leaf hash of those bytes must match what the tree holds: a
            // single-entry tree's root is its leaf hash.
            let mut root = [0u8; HASH_LEN];
            sentinel_root(h, root.as_mut_ptr());
            assert_eq!(crate::hash::hash_leaf(&buf[..len]), root);

            assert_eq!(
                sentinel_entry_canonical(h, 7, buf.as_mut_ptr(), buf.len(), &mut len),
                STATUS_NOT_FOUND
            );

            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn verify_integrity_through_the_boundary() {
        let path = temp_path("integrity");
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            for i in 0..16u64 {
                let p = format!("entry-{i}");
                let mut pos = 0u64;
                sentinel_append(h, p.as_ptr(), p.len(), &mut pos, ptr::null_mut());
            }
            let mut n = 0u64;
            assert_eq!(sentinel_verify_integrity(h, &mut n), STATUS_OK);
            assert_eq!(n, 16);
            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }

    #[test]
    fn reopen_through_the_boundary_reports_recovery() {
        let path = temp_path("reopen");
        let mut first_root = [0u8; HASH_LEN];
        unsafe {
            let h = sentinel_open(path.as_ptr(), 0, ptr::null_mut(), ptr::null_mut());
            for i in 0..25u64 {
                let p = format!("entry-{i}");
                let mut pos = 0u64;
                sentinel_append(h, p.as_ptr(), p.len(), &mut pos, ptr::null_mut());
            }
            sentinel_root(h, first_root.as_mut_ptr());
            sentinel_close(h);

            let mut loaded = 0u64;
            let mut discarded = 0u64;
            let h = sentinel_open(path.as_ptr(), 0, &mut loaded, &mut discarded);
            assert_eq!(loaded, 25);
            assert_eq!(discarded, 0);
            let mut root = [0u8; HASH_LEN];
            sentinel_root(h, root.as_mut_ptr());
            assert_eq!(root, first_root);
            sentinel_close(h);
        }
        let _ = std::fs::remove_file(path.to_str().unwrap());
    }
}
