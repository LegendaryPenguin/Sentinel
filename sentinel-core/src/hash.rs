//! Domain-separated tree hashing, following RFC 6962 §2.1.
//!
//! The prefixes are the whole point. Without them a leaf whose bytes happen
//! to equal `left || right` of some internal node hashes to the same value as
//! that node, which lets a prover present an interior node as a leaf and
//! claim an entry is in the log that never was. One byte of domain separation
//! removes the entire class.

use crate::sha256::Sha256;

/// A tree hash. 32 bytes, fixed, because the FFI boundary and the wire format
/// both want a size known at compile time.
pub type Hash = [u8; 32];

pub const HASH_LEN: usize = 32;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// The root of the empty tree is the hash of the empty string — *not* the
/// zero hash, and not the hash of the leaf prefix. RFC 6962 specifies this
/// and the choice matters: a verifier that uses zeros here will accept a
/// consistency proof from an empty tree against a forged root.
pub fn hash_empty() -> Hash {
    let h = Sha256::new();
    h.finish()
}

/// MTH({d}) = SHA-256(0x00 || d)
pub fn hash_leaf(entry: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(&[LEAF_PREFIX]);
    h.update(entry);
    h.finish()
}

/// MTH(left, right) = SHA-256(0x01 || left || right)
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(&[NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finish()
}

/// The largest power of two strictly less than `n`, which is the split point
/// RFC 6962 uses for every internal node.
///
/// Using *strictly less than* is what makes the tree left-complete: the left
/// subtree is always a perfect tree, so its hash never changes as the log
/// grows. That property is what lets consistency proofs be short, and getting
/// it wrong (for example by splitting at `n/2`) produces a tree that is
/// perfectly self-consistent and incompatible with every other
/// implementation, including the Go verifier in this repo.
pub fn split_point(n: u64) -> u64 {
    debug_assert!(n > 1, "split_point is only defined for n > 1");
    // The highest set bit of n-1: for n=2..=3 that is 2, for n=4..=7 it is 4.
    let bits = u64::BITS - (n - 1).leading_zeros();
    1u64 << (bits - 1)
}

pub fn to_hex(h: &Hash) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex characters. Returns `None` on any non-hex byte or a wrong
/// length, because a verifier handed a truncated root must fail rather than
/// silently zero-extend it.
pub fn from_hex(s: &str) -> Option<Hash> {
    let b = s.as_bytes();
    if b.len() != HASH_LEN * 2 {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        let hi = (b[i * 2] as char).to_digit(16)?;
        let lo = (b[i * 2 + 1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_sha256_of_empty_string() {
        assert_eq!(
            to_hex(&hash_empty()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rfc6962_leaf_vector() {
        // RFC 6962 test vector: MTH of a single empty leaf.
        assert_eq!(
            to_hex(&hash_leaf(b"")),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
    }

    #[test]
    fn leaf_and_node_domains_are_separate() {
        // Construct the exact collision the prefixes exist to prevent: a leaf
        // whose body is the concatenation of two child hashes.
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let node = hash_children(&a, &b);

        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        let leaf_of_concat = hash_leaf(&concat);

        assert_ne!(node, leaf_of_concat);
    }

    #[test]
    fn split_points_are_left_complete() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(7), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
        assert_eq!(split_point(1 << 20), 1 << 19);
        assert_eq!(split_point((1 << 20) + 1), 1 << 20);
    }

    #[test]
    fn split_point_always_leaves_both_sides_nonempty() {
        for n in 2..=4096u64 {
            let k = split_point(n);
            assert!(k >= 1 && k < n, "n={n} k={k}");
            assert!(k.is_power_of_two(), "n={n} k={k} is not a power of two");
            // The left subtree is perfect, so k is the largest power of two
            // below n: doubling it must reach or pass n.
            assert!(k * 2 >= n, "n={n} k={k} is not maximal");
        }
    }

    #[test]
    fn hex_round_trip_and_rejection() {
        let h = hash_leaf(b"round trip");
        assert_eq!(from_hex(&to_hex(&h)), Some(h));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex(&"z".repeat(64)), None);
        // One character short must fail rather than zero-pad.
        assert_eq!(from_hex(&to_hex(&h)[..63]), None);
    }
}
