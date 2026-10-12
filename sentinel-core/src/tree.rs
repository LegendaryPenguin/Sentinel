//! The authenticated tree over the log's leaves.
//!
//! The tree is **not** the source of truth. `log.rs` owns the persisted
//! entries; this structure is derived from them and can be thrown away and
//! rebuilt at any point. That ordering is deliberate — if the tree were
//! authoritative, a bug in the tree would be indistinguishable from a bug in
//! the log, and recovery would have nothing to recover *from*.
//!
//! Shape follows RFC 6962: every internal node splits at the largest power of
//! two strictly below its width, so the left subtree of any node is perfect
//! and its hash is final the moment it is complete. That is what makes the
//! cache below correct — a cached subtree hash can never need invalidating,
//! only extending.

use crate::hash::{hash_children, hash_empty, split_point, Hash};

/// Perfect-subtree hashes, indexed by level then by index within the level.
///
/// `levels[i][j]` covers leaves `[j * 2^i, (j+1) * 2^i)`. `levels[0]` is the
/// leaf hashes themselves. A node appears here only once its full range of
/// leaves exists, which is why entries are append-only and never rewritten:
/// the right-hand edge of the tree is computed on demand instead of being
/// stored and patched.
#[derive(Debug, Default, Clone)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree { levels: Vec::new() }
    }

    /// Rebuilds from a complete leaf sequence, as recovery does after a
    /// restart.
    pub fn from_leaves(leaves: &[Hash]) -> Self {
        let mut t = MerkleTree::new();
        for leaf in leaves {
            t.push(*leaf);
        }
        t
    }

    pub fn len(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends a leaf hash, promoting every perfect pair it completes.
    ///
    /// Amortised O(1) hashes per append: a leaf at index `i` completes a pair
    /// at level `k` exactly when `i+1` is divisible by `2^k`, so across `n`
    /// appends the promotions total `n-1`.
    pub fn push(&mut self, leaf: Hash) {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        self.levels[0].push(leaf);

        let mut level = 0;
        // A new complete pair exists at `level` whenever its length just
        // became even. Promote, then check whether that promotion in turn
        // completed a pair one level up.
        while self.levels[level].len() % 2 == 0 {
            let row = &self.levels[level];
            let n = row.len();
            let parent = hash_children(&row[n - 2], &row[n - 1]);
            if self.levels.len() == level + 1 {
                self.levels.push(Vec::new());
            }
            self.levels[level + 1].push(parent);
            level += 1;
        }
    }

    pub fn leaf(&self, index: u64) -> Option<Hash> {
        self.levels.first()?.get(index as usize).copied()
    }

    /// The current root.
    pub fn root(&self) -> Hash {
        self.root_at(self.len())
    }

    /// The root the log would have published when it held exactly `size`
    /// entries.
    ///
    /// Serving historical roots is not a convenience: a consistency proof is
    /// a statement relating two roots, and a verifier that cannot obtain the
    /// older root has nothing to check the proof against. Panics if `size`
    /// exceeds the current length, because a root for a future size is not a
    /// thing that exists and returning a plausible-looking hash would be
    /// worse than failing.
    pub fn root_at(&self, size: u64) -> Hash {
        assert!(
            size <= self.len(),
            "root_at({size}) requested on a tree of {} leaves",
            self.len()
        );
        if size == 0 {
            return hash_empty();
        }
        self.subtree(0, size)
    }

    /// MTH of leaves `[lo, hi)`.
    ///
    /// Hits the cache whenever the range is a perfect aligned subtree, which
    /// is every range the proof algorithms ask for except the ones straddling
    /// the tree's right edge. That makes `root_at` and both proof generators
    /// O(log n) hashes rather than O(n).
    pub fn subtree(&self, lo: u64, hi: u64) -> Hash {
        debug_assert!(lo < hi, "subtree({lo}, {hi}) is empty");
        debug_assert!(hi <= self.len(), "subtree({lo}, {hi}) runs past the tree");

        let width = hi - lo;
        if width.is_power_of_two() && lo % width == 0 {
            let level = width.trailing_zeros() as usize;
            let index = (lo / width) as usize;
            if let Some(h) = self.levels.get(level).and_then(|r| r.get(index)) {
                return *h;
            }
        }
        if width == 1 {
            // Unreachable in practice: a width-1 range is always aligned and
            // therefore served from levels[0] above. Kept as a guard so a
            // future cache change cannot turn this into infinite recursion.
            return self.levels[0][lo as usize];
        }

        let k = split_point(width);
        let left = self.subtree(lo, lo + k);
        let right = self.subtree(lo + k, hi);
        hash_children(&left, &right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{hash_leaf, to_hex};

    fn tree_of(n: u64) -> MerkleTree {
        let leaves: Vec<Hash> = (0..n)
            .map(|i| hash_leaf(format!("leaf-{i}").as_bytes()))
            .collect();
        MerkleTree::from_leaves(&leaves)
    }

    /// The RFC definition, written out directly and recursively with no cache.
    /// Slow and obviously correct, which is exactly what a reference should
    /// be: the cached implementation is checked against this rather than
    /// against itself.
    fn reference_mth(leaves: &[Hash]) -> Hash {
        match leaves.len() {
            0 => hash_empty(),
            1 => leaves[0],
            n => {
                let k = split_point(n as u64) as usize;
                hash_children(&reference_mth(&leaves[..k]), &reference_mth(&leaves[k..]))
            }
        }
    }

    #[test]
    fn empty_tree_root() {
        assert_eq!(MerkleTree::new().root(), hash_empty());
        assert_eq!(MerkleTree::new().len(), 0);
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let t = tree_of(1);
        assert_eq!(t.root(), hash_leaf(b"leaf-0"));
    }

    #[test]
    fn cached_root_matches_the_reference_at_every_size() {
        // Sizes up to 300 covers several powers of two and, more importantly,
        // the ragged sizes just above them where the right edge is deepest.
        let leaves: Vec<Hash> = (0..300u64)
            .map(|i| hash_leaf(format!("leaf-{i}").as_bytes()))
            .collect();
        let t = MerkleTree::from_leaves(&leaves);
        for n in 0..=300usize {
            assert_eq!(t.root_at(n as u64), reference_mth(&leaves[..n]), "size {n}");
        }
    }

    #[test]
    fn root_at_matches_a_tree_actually_built_to_that_size() {
        // root_at is a historical claim; it must equal what the tree really
        // published then, not merely what the reference recomputes now.
        for n in 0..=64u64 {
            assert_eq!(tree_of(300).root_at(n), tree_of(n).root(), "size {n}");
        }
    }

    #[test]
    fn appending_never_changes_an_earlier_root() {
        // The append-only property, stated as a test rather than as prose.
        let mut t = MerkleTree::new();
        let mut published = vec![t.root()];
        for i in 0..128u64 {
            t.push(hash_leaf(format!("leaf-{i}").as_bytes()));
            published.push(t.root());
            for (size, root) in published.iter().enumerate() {
                assert_eq!(
                    t.root_at(size as u64),
                    *root,
                    "root for size {size} changed"
                );
            }
        }
    }

    #[test]
    fn rfc6962_published_root_vectors() {
        // RFC 6962 §2.1.3 worked example: the tree over the eight-byte
        // sequence of leaves d0..d3 given in the specification. Pinning real
        // published vectors is what makes this implementation compatible with
        // other people's verifiers rather than merely self-consistent.
        let d: Vec<Hash> = [
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            vec![
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
                0x6e, 0x6f,
            ],
        ]
        .iter()
        .map(|b| hash_leaf(b))
        .collect();

        let t = MerkleTree::from_leaves(&d);
        // The eight-leaf root from the RFC's example tree.
        assert_eq!(
            to_hex(&t.root()),
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
        );
        // And the intermediate roots the same example gives.
        assert_eq!(
            to_hex(&t.root_at(1)),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_eq!(
            to_hex(&t.root_at(2)),
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"
        );
        assert_eq!(
            to_hex(&t.root_at(3)),
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"
        );
        assert_eq!(
            to_hex(&t.root_at(4)),
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
        );
    }

    #[test]
    fn subtree_hashes_compose() {
        let t = tree_of(100);
        // Any split must recombine to the whole, at every split point.
        for hi in 2..=100u64 {
            let k = split_point(hi);
            let combined = hash_children(&t.subtree(0, k), &t.subtree(k, hi));
            assert_eq!(combined, t.root_at(hi), "hi={hi}");
        }
    }

    #[test]
    fn leaf_accessor_bounds() {
        let t = tree_of(3);
        assert_eq!(t.leaf(0), Some(hash_leaf(b"leaf-0")));
        assert_eq!(t.leaf(2), Some(hash_leaf(b"leaf-2")));
        assert_eq!(t.leaf(3), None);
        assert_eq!(MerkleTree::new().leaf(0), None);
    }

    #[test]
    #[should_panic(expected = "root_at(5)")]
    fn root_for_a_future_size_panics() {
        tree_of(3).root_at(5);
    }

    #[test]
    fn distinct_leaves_give_distinct_roots() {
        // Guards against a tree that ignores its input, which every other
        // test here would otherwise pass.
        let mut seen = std::collections::HashSet::new();
        for n in 1..=64u64 {
            assert!(seen.insert(tree_of(n).root()), "duplicate root at size {n}");
        }
    }
}
