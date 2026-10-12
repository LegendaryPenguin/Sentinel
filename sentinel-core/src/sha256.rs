//! SHA-256, implemented here rather than imported.
//!
//! A transparency log that depends on a hash library it did not write has
//! moved the interesting part of the problem somewhere else. More usefully:
//! the Go verifier in `go/verify` hashes with `crypto/sha256` from the
//! standard library, so every root this module computes is checked against a
//! completely separate implementation. Two independent implementations
//! agreeing on a root is evidence; one implementation agreeing with itself is
//! not. That cross-check is the reason this file exists and is also why it
//! must not be replaced with a crate dependency.
//!
//! FIPS 180-4. No SIMD, no assembly, no attempt at being fast — the log's
//! cost is dominated by fsync, measured in `bench/`, not by compression.

/// Round constants: the first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Initial state: the first 32 bits of the fractional parts of the square
/// roots of the first 8 primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLOCK: usize = 64;

/// A streaming SHA-256. Streaming rather than one-shot because a leaf hash
/// covers a prefix byte followed by an entry body, and concatenating those
/// into a scratch buffer per hash is an allocation the tree build does
/// hundreds of thousands of times.
pub struct Sha256 {
    state: [u32; 8],
    /// Partial block awaiting more input. Only the first `buffered` bytes are
    /// meaningful.
    buf: [u8; BLOCK],
    buffered: usize,
    /// Total message length in bytes, for the length suffix in the padding.
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: H0,
            buf: [0u8; BLOCK],
            buffered: 0,
            total: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self
            .total
            .checked_add(data.len() as u64)
            .expect("sha256: message length overflows u64");

        // Top off a partial block first, so the fast path below can assume an
        // empty buffer and consume whole blocks straight out of `data`.
        if self.buffered > 0 {
            let want = BLOCK - self.buffered;
            let take = want.min(data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == BLOCK {
                let block = self.buf;
                self.compress(&block);
                self.buffered = 0;
            }
        }

        while data.len() >= BLOCK {
            let mut block = [0u8; BLOCK];
            block.copy_from_slice(&data[..BLOCK]);
            self.compress(&block);
            data = &data[BLOCK..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        // Padding: 0x80, then zeros, then the length in bits as a big-endian
        // u64 occupying the last 8 bytes of the final block.
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != BLOCK - 8 {
            self.update(&[0x00]);
        }
        self.update(&bitlen.to_be_bytes());
        debug_assert_eq!(self.buffered, 0, "padding must land on a block boundary");

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; BLOCK]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (slot, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(v);
        }
    }
}

/// One-shot convenience for callers that already hold the whole message.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fips_180_4_vectors() {
        // The empty string, which is also the root of an empty Merkle tree.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a() {
        // Exercises the multi-block path and the length suffix at a size that
        // is not a block multiple.
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_matches_one_shot_at_every_split() {
        // A bug in the partial-block logic typically survives one-shot hashing
        // and only shows up at a particular split, so try all of them across a
        // range that spans several block boundaries.
        let msg: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let want = sha256(&msg);
        for split in 0..=msg.len() {
            let mut h = Sha256::new();
            h.update(&msg[..split]);
            h.update(&msg[split..]);
            assert_eq!(h.finish(), want, "split at {split}");
        }
    }

    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let msg: Vec<u8> = (0..130u32).map(|i| (i * 7 % 256) as u8).collect();
        let mut h = Sha256::new();
        for b in &msg {
            h.update(&[*b]);
        }
        assert_eq!(h.finish(), sha256(&msg));
    }

    #[test]
    fn exact_block_multiples() {
        // 55/56/57 and 63/64/65 are where padding either just fits, needs a
        // whole extra block, or spills — the classic off-by-one sites.
        for n in [
            0usize, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129,
        ] {
            let msg = vec![b'x'; n];
            let mut h = Sha256::new();
            h.update(&msg);
            let streamed = h.finish();
            assert_eq!(streamed, sha256(&msg), "length {n}");
        }
    }
}
