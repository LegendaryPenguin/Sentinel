//! Entries, and the two different byte encodings each one has.
//!
//! An entry is encoded twice, for two different consumers, and conflating
//! them is the bug this module is shaped to prevent:
//!
//!   * **Canonical form** is what gets hashed into the tree. It is the
//!     contract between this crate and every verifier, including ones written
//!     in other languages by people who cannot read this file. It must never
//!     change, and it carries no framing.
//!
//!   * **Storage form** is canonical form wrapped in a length prefix and a
//!     CRC so a partially written tail can be told apart from a complete
//!     record. It is private to the log file and may change freely, because
//!     nothing outside this process ever sees it.
//!
//! Everything is big-endian. That is a deliberate departure from the
//! little-endian framing I used in Cairn: there the bytes never left the
//! process, so native order was free. Here the canonical bytes cross into Go
//! and get hashed, and a byte-order disagreement between producer and
//! verifier shows up as "the proof does not verify" with nothing in either
//! implementation looking wrong. One order everywhere removes the class.

use crate::crc32c;

/// Position, timestamp, payload length.
pub const CANONICAL_HEADER: usize = 8 + 8 + 4;

/// Length prefix and CRC added by the storage framing.
const LEN_PREFIX: usize = 4;
const CRC_LEN: usize = 4;

/// Caps how much a single corrupted length field can make the reader allocate
/// before the CRC has a chance to reject it. 16 MiB is far above any entry
/// this log is for and far below a size that matters.
pub const MAX_PAYLOAD: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Zero-based index in the log. Also this entry's leaf index in the tree,
    /// which is why it is assigned by the log and not by the caller.
    pub position: u64,
    /// Nanoseconds since the Unix epoch, recorded by the server at append.
    ///
    /// Hashed into the leaf, which means a verifier must be handed the
    /// timestamp and cannot reconstruct the leaf from the payload alone. That
    /// is the intended trade: the log commits to *when* it claims to have
    /// seen something, and cannot later revise that without breaking every
    /// proof it has already issued.
    pub timestamp_nanos: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the header needs. On the storage path this is the
    /// expected shape of a torn tail, not corruption.
    Truncated,
    /// Header parsed, but the declared payload length runs past the buffer.
    LengthMismatch { declared: usize, available: usize },
    /// Declared payload exceeds `MAX_PAYLOAD`.
    PayloadTooLarge(usize),
    /// Framing decoded but the CRC does not match. The bytes present are a
    /// complete record that is not the record that was written, which is a
    /// different and much more serious condition than `Truncated`.
    BadChecksum { want: u32, got: u32 },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "record truncated"),
            DecodeError::LengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "declared payload {declared} exceeds {available} available bytes"
                )
            }
            DecodeError::PayloadTooLarge(n) => {
                write!(f, "payload {n} exceeds maximum {MAX_PAYLOAD}")
            }
            DecodeError::BadChecksum { want, got } => {
                write!(f, "checksum mismatch: want {want:#010x}, got {got:#010x}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl Entry {
    /// The bytes that get hashed into the leaf.
    ///
    ///   u64  position
    ///   u64  timestamp_nanos
    ///   u32  payload_len
    ///   []   payload
    ///
    /// The length is included even though the payload runs to the end of the
    /// buffer. Without it, `(position, ts, "ab")` and a hypothetical future
    /// encoding that appended a second field would be able to produce
    /// identical canonical bytes from different entries, and a log that can be
    /// extended is a log where that eventually happens.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CANONICAL_HEADER + self.payload.len());
        out.extend_from_slice(&self.position.to_be_bytes());
        out.extend_from_slice(&self.timestamp_nanos.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Inverse of `canonical`. Used by tests and by the verifier CLI, which
    /// receives canonical bytes over the wire and needs to show the operator
    /// what it is about to verify.
    pub fn from_canonical(buf: &[u8]) -> Result<Entry, DecodeError> {
        if buf.len() < CANONICAL_HEADER {
            return Err(DecodeError::Truncated);
        }
        let position = u64::from_be_bytes(buf[0..8].try_into().unwrap());
        let timestamp_nanos = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let payload_len = u32::from_be_bytes(buf[16..20].try_into().unwrap()) as usize;
        if payload_len > MAX_PAYLOAD {
            return Err(DecodeError::PayloadTooLarge(payload_len));
        }
        let available = buf.len() - CANONICAL_HEADER;
        if payload_len != available {
            return Err(DecodeError::LengthMismatch {
                declared: payload_len,
                available,
            });
        }
        Ok(Entry {
            position,
            timestamp_nanos,
            payload: buf[CANONICAL_HEADER..].to_vec(),
        })
    }

    /// Canonical form wrapped for the log file:
    ///
    ///   u32  body_len   bytes of canonical form that follow
    ///   []   canonical
    ///   u32  crc32c     over the length prefix and the body together
    ///
    /// The CRC covers the length prefix on purpose. A corrupted length that
    /// is not covered can steer the reader onto a boundary where some *other*
    /// record's bytes happen to checksum correctly, and the reader then
    /// reports success on a log it has misparsed.
    pub fn encode_storage(&self) -> Vec<u8> {
        let body = self.canonical();
        let mut out = Vec::with_capacity(LEN_PREFIX + body.len() + CRC_LEN);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        let crc = crc32c::checksum(&out);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    /// Reads one record from the front of `buf`, returning the entry and the
    /// number of bytes consumed.
    ///
    /// `Truncated` means "there is not a whole record here", which at the end
    /// of a file is a torn write and recoverable. Any other error means the
    /// bytes are a complete record that fails its own integrity check, which
    /// the log treats as unrecoverable — see `log.rs` for why skipping it
    /// would be the same thing as rewriting history.
    pub fn decode_storage(buf: &[u8]) -> Result<(Entry, usize), DecodeError> {
        if buf.len() < LEN_PREFIX {
            return Err(DecodeError::Truncated);
        }
        let body_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        if body_len > MAX_PAYLOAD + CANONICAL_HEADER {
            return Err(DecodeError::PayloadTooLarge(body_len));
        }
        let total = LEN_PREFIX + body_len + CRC_LEN;
        if buf.len() < total {
            return Err(DecodeError::Truncated);
        }
        let want = u32::from_be_bytes(buf[LEN_PREFIX + body_len..total].try_into().unwrap());
        let got = crc32c::checksum(&buf[..LEN_PREFIX + body_len]);
        if want != got {
            return Err(DecodeError::BadChecksum { want, got });
        }
        let entry = Entry::from_canonical(&buf[LEN_PREFIX..LEN_PREFIX + body_len])?;
        Ok((entry, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pos: u64, payload: &[u8]) -> Entry {
        Entry {
            position: pos,
            timestamp_nanos: 1_700_000_000_000_000_000,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn canonical_round_trip() {
        for payload in [
            b"".as_slice(),
            b"x",
            b"a longer payload with bytes \x00\xff",
        ] {
            let e = entry(7, payload);
            assert_eq!(Entry::from_canonical(&e.canonical()).unwrap(), e);
        }
    }

    #[test]
    fn storage_round_trip_reports_exact_length() {
        let e = entry(3, b"hello");
        let bytes = e.encode_storage();
        let (got, n) = Entry::decode_storage(&bytes).unwrap();
        assert_eq!(got, e);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn concatenated_records_decode_in_sequence() {
        let mut buf = Vec::new();
        for i in 0..5u64 {
            buf.extend_from_slice(&entry(i, format!("entry-{i}").as_bytes()).encode_storage());
        }
        let mut off = 0;
        for i in 0..5u64 {
            let (e, n) = Entry::decode_storage(&buf[off..]).unwrap();
            assert_eq!(e.position, i);
            off += n;
        }
        assert_eq!(off, buf.len());
    }

    #[test]
    fn every_truncation_is_reported_as_truncated() {
        // This is the property the recovery path depends on: a short buffer
        // must never be reported as corruption, or a torn tail would be
        // treated as a tampered log.
        let bytes = entry(1, b"payload").encode_storage();
        for n in 0..bytes.len() {
            assert_eq!(
                Entry::decode_storage(&bytes[..n]),
                Err(DecodeError::Truncated),
                "prefix of length {n}"
            );
        }
    }

    #[test]
    fn corruption_anywhere_in_the_record_is_caught() {
        let bytes = entry(1, b"payload").encode_storage();
        for i in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[i] ^= 0x01;
            match Entry::decode_storage(&corrupt) {
                Err(DecodeError::BadChecksum { .. }) => {}
                // Flipping a low bit of the length prefix changes how many
                // bytes the record claims; the buffer is then too short and
                // Truncated is the honest answer. Either way it is rejected.
                Err(DecodeError::Truncated) => {}
                Err(DecodeError::LengthMismatch { .. }) => {}
                // Corrupting a high byte of the length prefix inflates the
                // declared size past MAX_PAYLOAD, which is caught before any
                // allocation happens. Also a rejection.
                Err(DecodeError::PayloadTooLarge(_)) => {}
                other => panic!("byte {i} corruption accepted or misreported: {other:?}"),
            }
        }
    }

    #[test]
    fn declared_length_past_the_buffer_is_rejected() {
        let e = entry(1, b"abc");
        let mut canon = e.canonical();
        // Claim a longer payload than the buffer holds.
        canon[16..20].copy_from_slice(&999u32.to_be_bytes());
        assert!(matches!(
            Entry::from_canonical(&canon),
            Err(DecodeError::LengthMismatch { declared: 999, .. })
        ));
    }

    #[test]
    fn absurd_length_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            Entry::decode_storage(&buf),
            Err(DecodeError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn position_and_timestamp_both_change_the_canonical_bytes() {
        // Both fields are hashed, so neither may be silently revisable.
        let a = entry(1, b"same payload");
        let mut b = a.clone();
        b.position = 2;
        let mut c = a.clone();
        c.timestamp_nanos += 1;
        assert_ne!(a.canonical(), b.canonical());
        assert_ne!(a.canonical(), c.canonical());
    }
}
