//! CRC-32C (Castagnoli), table-driven.
//!
//! Guards the storage framing, not the tree. The tree is protected by SHA-256
//! and a CRC there would be security theatre; the framing needs a cheap
//! integrity check that distinguishes "this record was never fully written"
//! from "these bytes decode to a plausible record that is not the one we
//! wrote". Castagnoli rather than the IEEE polynomial because it is the
//! polynomial with hardware support on the machines this runs on, so the
//! check does not become the reason fsync looks cheap.

const POLY: u32 = 0x82f6_3b78; // Castagnoli, bit-reflected

/// Built once at first use. A const-fn table would be nicer but the loop
/// below is a few microseconds and runs on a path that already opens a file.
fn table() -> &'static [u32; 256] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ POLY
                } else {
                    crc >> 1
                };
            }
            *slot = crc;
        }
        t
    })
}

pub fn checksum(data: &[u8]) -> u32 {
    let t = table();
    let mut crc = !0u32;
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // The two values the CRC catalogue pins down for CRC-32C. Other
        // strings are deliberately not asserted here: a vector I cannot cite
        // is a vector that encodes whatever this implementation happens to
        // do, which is worse than no vector at all. The cross-language check
        // against Go's `hash/crc32` Castagnoli table lives in the Go tests.
        assert_eq!(checksum(b""), 0x0000_0000);
        assert_eq!(checksum(b"123456789"), 0xe306_9283);
    }

    #[test]
    fn single_bit_flips_are_detected() {
        let data = b"a record body of some length".to_vec();
        let want = checksum(&data);
        for byte in 0..data.len() {
            for bit in 0..8 {
                let mut corrupt = data.clone();
                corrupt[byte] ^= 1 << bit;
                assert_ne!(checksum(&corrupt), want, "byte {byte} bit {bit}");
            }
        }
    }
}
