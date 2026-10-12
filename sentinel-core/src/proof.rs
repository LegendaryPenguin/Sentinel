//! Inclusion and consistency proofs: generation, and verification.
//!
//! Generation follows the recursive definitions in RFC 6962 §2.1.1 and
//! §2.1.2 almost literally, because the recursive form is the one that is
//! obviously the same as the specification. Verification uses the iterative
//! form instead, and that asymmetry is on purpose: a verifier must not need
//! the tree, only the proof, the sizes, and the roots. If verification shared
//! the tree-walking code with generation, a tree bug would be invisible —
//! the proof and the check would be wrong in the same direction.
//!
//! Both verifiers are also reimplemented independently in Go, in
//! `go/verify`. Three implementations is not excessive for a structure whose
//! entire value is that nobody has to trust the server.

use crate::hash::{hash_children, hash_empty, split_point, Hash};
use crate::tree::MerkleTree;

/// Why a proof was rejected.
///
/// These are deliberately specific. "Proof invalid" tells an operator
/// nothing, and the difference between "this proof is the wrong length for a
/// tree of this size" and "this proof is well-formed and the root does not
/// match" is the difference between a client bug and a log that is lying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// `index >= size`: an entry beyond the end of the tree.
    IndexOutOfRange { index: u64, size: u64 },
    /// `first > second`: consistency runs forward only.
    SizesReversed { first: u64, second: u64 },
    /// Fewer hashes than the tree size requires.
    TooShort { have: usize },
    /// More hashes than the tree size allows. Rejected rather than ignored:
    /// trailing nodes are the shape of a prover feeling out what a verifier
    /// will tolerate.
    TooLong { have: usize, used: usize },
    /// The proof is well-formed but recomputes a different root. This is the
    /// one that means tampering.
    RootMismatch { computed: Hash, expected: Hash },
    /// A proof was supplied where the protocol requires none.
    ExpectedEmpty { have: usize },
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::hash::to_hex;
        match self {
            ProofError::IndexOutOfRange { index, size } => {
                write!(f, "leaf index {index} is outside a tree of {size} entries")
            }
            ProofError::SizesReversed { first, second } => {
                write!(f, "first size {first} exceeds second size {second}")
            }
            ProofError::TooShort { have } => write!(f, "proof too short: {have} nodes"),
            ProofError::TooLong { have, used } => {
                write!(f, "proof too long: {have} nodes supplied, {used} consumed")
            }
            ProofError::RootMismatch { computed, expected } => write!(
                f,
                "root mismatch: computed {}, expected {}",
                to_hex(computed),
                to_hex(expected)
            ),
            ProofError::ExpectedEmpty { have } => {
                write!(f, "expected an empty proof, got {have} nodes")
            }
        }
    }
}

impl std::error::Error for ProofError {}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

impl MerkleTree {
    /// PATH(index, D[size]) from RFC 6962 §2.1.1.
    ///
    /// Ordered leaf-first: the sibling nearest the leaf comes first, which is
    /// the order the iterative verifier consumes.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>, ProofError> {
        if index >= size {
            return Err(ProofError::IndexOutOfRange { index, size });
        }
        assert!(size <= self.len(), "inclusion_proof beyond the tree");
        Ok(self.path(0, size, index))
    }

    fn path(&self, lo: u64, hi: u64, index: u64) -> Vec<Hash> {
        if hi - lo == 1 {
            return Vec::new();
        }
        let k = split_point(hi - lo);
        if index < lo + k {
            let mut p = self.path(lo, lo + k, index);
            p.push(self.subtree(lo + k, hi));
            p
        } else {
            let mut p = self.path(lo + k, hi, index);
            p.push(self.subtree(lo, lo + k));
            p
        }
    }

    /// PROOF(first, D[second]) from RFC 6962 §2.1.2.
    ///
    /// The proof lets a verifier holding the root at `first` establish that
    /// the root at `second` was produced by *appending* to it — not by
    /// rewriting any part of it.
    pub fn consistency_proof(&self, first: u64, second: u64) -> Result<Vec<Hash>, ProofError> {
        if first > second {
            return Err(ProofError::SizesReversed { first, second });
        }
        assert!(second <= self.len(), "consistency_proof beyond the tree");
        // A tree is trivially consistent with itself, and every tree is
        // consistent with the empty tree. Both cases carry no nodes, and the
        // verifier enforces that they carry none.
        if first == 0 || first == second {
            return Ok(Vec::new());
        }
        Ok(self.subproof(first, 0, second, true))
    }

    fn subproof(&self, m: u64, lo: u64, hi: u64, complete: bool) -> Vec<Hash> {
        let n = hi - lo;
        if m == n {
            // The old tree is exactly this subtree. If the caller already
            // knows its hash (it is the old root, or a node the verifier can
            // rebuild) it need not be sent; otherwise it must be.
            return if complete {
                Vec::new()
            } else {
                vec![self.subtree(lo, hi)]
            };
        }
        let k = split_point(n);
        if m <= k {
            let mut p = self.subproof(m, lo, lo + k, complete);
            p.push(self.subtree(lo + k, hi));
            p
        } else {
            let mut p = self.subproof(m - k, lo + k, hi, false);
            p.push(self.subtree(lo, lo + k));
            p
        }
    }
}

// ---------------------------------------------------------------------------
// Verification — tree-free by construction
// ---------------------------------------------------------------------------

/// Checks that `leaf_hash` sits at `index` in a tree of `size` whose root is
/// `root`.
///
/// Takes no tree and no log. Everything it needs is in the arguments, which
/// is what makes it usable by an auditor who has only ever seen the log's
/// HTTP responses.
pub fn verify_inclusion(
    index: u64,
    size: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
    root: &Hash,
) -> Result<(), ProofError> {
    if index >= size {
        return Err(ProofError::IndexOutOfRange { index, size });
    }

    // `node` walks up the tree from the leaf; `last` is the index of the
    // rightmost node at the same level. The pair is what lets the loop know
    // whether a node has a sibling at all without materialising the tree:
    // when `node == last` the node is the right edge and is carried up
    // unchanged.
    let mut node = index;
    let mut last = size - 1;
    let mut computed = *leaf_hash;
    let mut used = 0usize;

    while last > 0 {
        if node % 2 == 1 {
            // Right child: sibling is on the left.
            let sibling = proof
                .get(used)
                .ok_or(ProofError::TooShort { have: proof.len() })?;
            computed = hash_children(sibling, &computed);
            used += 1;
        } else if node < last {
            // Left child with a sibling present.
            let sibling = proof
                .get(used)
                .ok_or(ProofError::TooShort { have: proof.len() })?;
            computed = hash_children(&computed, sibling);
            used += 1;
        }
        // node == last and even: no sibling at this level, carry upward.
        node /= 2;
        last /= 2;
    }

    if used != proof.len() {
        return Err(ProofError::TooLong {
            have: proof.len(),
            used,
        });
    }
    if computed != *root {
        return Err(ProofError::RootMismatch {
            computed,
            expected: *root,
        });
    }
    Ok(())
}

/// Checks that a tree of `second` entries with root `second_root` is an
/// append-only extension of a tree of `first` entries with root
/// `first_root`.
///
/// Recomputing *both* roots is the load-bearing part. A verifier that only
/// rebuilds the new root proves the proof is well-formed against the new
/// tree, which is not the claim being made; the claim is that the old root is
/// embedded in the new one, and that requires deriving the old root from the
/// same nodes.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> Result<(), ProofError> {
    if first > second {
        return Err(ProofError::SizesReversed { first, second });
    }
    if first == second {
        if !proof.is_empty() {
            return Err(ProofError::ExpectedEmpty { have: proof.len() });
        }
        if first_root != second_root {
            return Err(ProofError::RootMismatch {
                computed: *first_root,
                expected: *second_root,
            });
        }
        return Ok(());
    }
    if first == 0 {
        // Every tree extends the empty tree, so there is nothing to prove —
        // but a proof must not be smuggled in alongside that fact.
        if !proof.is_empty() {
            return Err(ProofError::ExpectedEmpty { have: proof.len() });
        }
        if *first_root != hash_empty() {
            return Err(ProofError::RootMismatch {
                computed: hash_empty(),
                expected: *first_root,
            });
        }
        return Ok(());
    }

    let mut node = first - 1;
    let mut last = second - 1;
    // Climb to the root of the old tree's rightmost complete subtree. Those
    // levels are entirely inside the old tree, so they contribute no proof
    // nodes.
    while node % 2 == 1 {
        node /= 2;
        last /= 2;
    }

    let mut used = 0usize;
    // If the old tree is a perfect subtree of the new one (`first` a power of
    // two), its root is a node of the new tree and the prover need not resend
    // it. Otherwise the first proof node is the old tree's right-edge node,
    // and it seeds both reconstructions.
    let (mut old, mut new) = if node > 0 {
        let seed = proof
            .first()
            .ok_or(ProofError::TooShort { have: proof.len() })?;
        used = 1;
        (*seed, *seed)
    } else {
        (*first_root, *first_root)
    };

    while node > 0 {
        if last == 0 {
            return Err(ProofError::TooShort { have: proof.len() });
        }
        if node % 2 == 1 {
            // A left sibling that both trees share.
            let sibling = proof
                .get(used)
                .ok_or(ProofError::TooShort { have: proof.len() })?;
            old = hash_children(sibling, &old);
            new = hash_children(sibling, &new);
            used += 1;
        } else if node < last {
            // A right sibling that exists only in the new tree. The old
            // reconstruction deliberately does not absorb it — that is the
            // step where "appended" is distinguished from "rewritten".
            let sibling = proof
                .get(used)
                .ok_or(ProofError::TooShort { have: proof.len() })?;
            new = hash_children(&new, sibling);
            used += 1;
        }
        node /= 2;
        last /= 2;
    }

    if old != *first_root {
        return Err(ProofError::RootMismatch {
            computed: old,
            expected: *first_root,
        });
    }

    // Fold in whatever the new tree grew on its right edge above the old
    // tree's root.
    while last > 0 {
        let sibling = proof
            .get(used)
            .ok_or(ProofError::TooShort { have: proof.len() })?;
        new = hash_children(&new, sibling);
        used += 1;
        last /= 2;
    }

    if new != *second_root {
        return Err(ProofError::RootMismatch {
            computed: new,
            expected: *second_root,
        });
    }
    if used != proof.len() {
        return Err(ProofError::TooLong {
            have: proof.len(),
            used,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_leaf;

    fn leaves(n: u64) -> Vec<Hash> {
        (0..n)
            .map(|i| hash_leaf(format!("leaf-{i}").as_bytes()))
            .collect()
    }

    fn tree(n: u64) -> MerkleTree {
        MerkleTree::from_leaves(&leaves(n))
    }

    #[test]
    fn inclusion_holds_for_every_index_at_every_size() {
        // The exhaustive sweep is the test that matters. Odd sizes, sizes one
        // past a power of two, and the last leaf of a ragged tree are each
        // where a hand-written proof walk goes wrong, and checking only a few
        // sizes reliably misses at least one of them.
        for size in 1..=130u64 {
            let t = tree(size);
            let root = t.root_at(size);
            for index in 0..size {
                let proof = t.inclusion_proof(index, size).unwrap();
                let leaf = t.leaf(index).unwrap();
                verify_inclusion(index, size, &leaf, &proof, &root)
                    .unwrap_or_else(|e| panic!("size {size} index {index}: {e}"));
            }
        }
    }

    #[test]
    fn inclusion_proof_length_is_logarithmic() {
        let t = tree(1024);
        for index in 0..1024u64 {
            assert_eq!(t.inclusion_proof(index, 1024).unwrap().len(), 10);
        }
        // A ragged tree's proofs vary in length but stay within the bound.
        let t = tree(1000);
        for index in 0..1000u64 {
            assert!(t.inclusion_proof(index, 1000).unwrap().len() <= 10);
        }
    }

    #[test]
    fn inclusion_against_a_historical_size() {
        // Proofs are issued against a published root, which is usually not
        // the current one.
        let t = tree(200);
        for size in [1u64, 2, 3, 7, 8, 9, 100, 199, 200] {
            let root = t.root_at(size);
            for index in 0..size {
                let proof = t.inclusion_proof(index, size).unwrap();
                verify_inclusion(index, size, &t.leaf(index).unwrap(), &proof, &root).unwrap();
            }
        }
    }

    #[test]
    fn consistency_holds_for_every_pair_of_sizes() {
        let t = tree(90);
        for second in 1..=90u64 {
            let second_root = t.root_at(second);
            for first in 0..=second {
                let first_root = t.root_at(first);
                let proof = t.consistency_proof(first, second).unwrap();
                verify_consistency(first, second, &first_root, &second_root, &proof)
                    .unwrap_or_else(|e| panic!("{first} -> {second}: {e}"));
            }
        }
    }

    #[test]
    fn a_rewritten_entry_breaks_inclusion() {
        let size = 37u64;
        let mut ls = leaves(size);
        let honest = MerkleTree::from_leaves(&ls);
        let honest_root = honest.root();

        // Replace one entry and keep everything else. This is the attack the
        // whole structure exists to detect.
        ls[11] = hash_leaf(b"substituted");
        let forged = MerkleTree::from_leaves(&ls);

        assert_ne!(forged.root(), honest_root);

        // A proof from the forged tree cannot be made to verify against the
        // honest published root, for the altered leaf or for any other.
        for index in 0..size {
            let proof = forged.inclusion_proof(index, size).unwrap();
            let leaf = forged.leaf(index).unwrap();
            let r = verify_inclusion(index, size, &leaf, &proof, &honest_root);
            assert!(
                matches!(r, Err(ProofError::RootMismatch { .. })),
                "index {index} verified"
            );
        }
    }

    #[test]
    fn a_rewritten_history_breaks_consistency() {
        // Build a log, publish a root, then rewrite an old entry and keep
        // appending. The new tree is internally perfect; consistency with the
        // published root is what exposes it.
        let first = 20u64;
        let mut ls = leaves(50);
        let honest_old_root = MerkleTree::from_leaves(&ls[..first as usize]).root();

        ls[5] = hash_leaf(b"rewritten history");
        let forged = MerkleTree::from_leaves(&ls);
        let forged_root = forged.root();
        let proof = forged.consistency_proof(first, 50).unwrap();

        let r = verify_consistency(first, 50, &honest_old_root, &forged_root, &proof);
        assert!(
            matches!(r, Err(ProofError::RootMismatch { .. })),
            "forged history accepted"
        );
    }

    #[test]
    fn truncated_history_breaks_consistency() {
        // Dropping entries is the other half of rewriting them.
        let full = tree(40);
        let shorter = tree(30);
        let proof = full.consistency_proof(30, 40).unwrap();
        // Claim the 40-entry log extends a *different* 30-entry log.
        let wrong_old_root = MerkleTree::from_leaves(&{
            let mut l = leaves(30);
            l[29] = hash_leaf(b"different last entry");
            l
        })
        .root();
        assert_ne!(wrong_old_root, shorter.root());
        let r = verify_consistency(30, 40, &wrong_old_root, &full.root(), &proof);
        assert!(matches!(r, Err(ProofError::RootMismatch { .. })));
    }

    #[test]
    fn missing_proof_nodes_are_rejected() {
        let t = tree(64);
        let root = t.root();
        let proof = t.inclusion_proof(13, 64).unwrap();
        for drop in 0..proof.len() {
            let mut short = proof.clone();
            short.remove(drop);
            let r = verify_inclusion(13, 64, &t.leaf(13).unwrap(), &short, &root);
            assert!(r.is_err(), "proof with node {drop} removed verified");
        }
    }

    #[test]
    fn extra_proof_nodes_are_rejected() {
        let t = tree(64);
        let mut proof = t.inclusion_proof(13, 64).unwrap();
        proof.push(hash_leaf(b"extra"));
        assert!(matches!(
            verify_inclusion(13, 64, &t.leaf(13).unwrap(), &proof, &t.root()),
            Err(ProofError::TooLong { .. })
        ));
    }

    #[test]
    fn corrupted_proof_nodes_are_rejected() {
        let t = tree(100);
        let root = t.root();
        let proof = t.inclusion_proof(42, 100).unwrap();
        for i in 0..proof.len() {
            for bit in [0u8, 7] {
                let mut bad = proof.clone();
                bad[i][0] ^= 1 << bit;
                assert!(
                    verify_inclusion(42, 100, &t.leaf(42).unwrap(), &bad, &root).is_err(),
                    "node {i} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn reordered_proof_nodes_are_rejected() {
        // Order carries meaning: swapping two siblings changes which side of
        // the concatenation each lands on.
        let t = tree(64);
        let proof = t.inclusion_proof(13, 64).unwrap();
        for i in 0..proof.len() - 1 {
            let mut swapped = proof.clone();
            swapped.swap(i, i + 1);
            assert!(
                verify_inclusion(13, 64, &t.leaf(13).unwrap(), &swapped, &t.root()).is_err(),
                "swap {i}"
            );
        }
    }

    #[test]
    fn a_proof_for_one_index_does_not_verify_at_another() {
        let t = tree(50);
        let root = t.root();
        let proof = t.inclusion_proof(10, 50).unwrap();
        for index in 0..50u64 {
            if index == 10 {
                continue;
            }
            let r = verify_inclusion(index, 50, &t.leaf(index).unwrap(), &proof, &root);
            assert!(r.is_err(), "proof for 10 verified at {index}");
        }
    }

    #[test]
    fn stale_root_is_rejected() {
        // A log that answers a proof request for size 60 with a root from
        // size 50 must be caught.
        let t = tree(60);
        let proof = t.inclusion_proof(3, 60).unwrap();
        let stale = t.root_at(50);
        assert!(verify_inclusion(3, 60, &t.leaf(3).unwrap(), &proof, &stale).is_err());
    }

    #[test]
    fn out_of_range_index_is_rejected_before_hashing() {
        let t = tree(10);
        assert_eq!(
            t.inclusion_proof(10, 10),
            Err(ProofError::IndexOutOfRange {
                index: 10,
                size: 10
            })
        );
        assert_eq!(
            verify_inclusion(10, 10, &hash_leaf(b"x"), &[], &t.root()),
            Err(ProofError::IndexOutOfRange {
                index: 10,
                size: 10
            })
        );
    }

    #[test]
    fn reversed_sizes_are_rejected() {
        let t = tree(10);
        assert_eq!(
            t.consistency_proof(8, 5),
            Err(ProofError::SizesReversed {
                first: 8,
                second: 5
            })
        );
        assert_eq!(
            verify_consistency(8, 5, &t.root_at(8), &t.root_at(5), &[]),
            Err(ProofError::SizesReversed {
                first: 8,
                second: 5
            })
        );
    }

    #[test]
    fn equal_sizes_require_an_empty_proof_and_equal_roots() {
        let t = tree(10);
        let root = t.root();
        verify_consistency(10, 10, &root, &root, &[]).unwrap();
        assert!(matches!(
            verify_consistency(10, 10, &root, &root, &[hash_leaf(b"x")]),
            Err(ProofError::ExpectedEmpty { .. })
        ));
        assert!(matches!(
            verify_consistency(10, 10, &root, &hash_leaf(b"other"), &[]),
            Err(ProofError::RootMismatch { .. })
        ));
    }

    #[test]
    fn empty_first_tree_requires_the_empty_root() {
        let t = tree(10);
        verify_consistency(0, 10, &hash_empty(), &t.root(), &[]).unwrap();
        // The zero hash is a common and wrong choice for the empty root.
        assert!(matches!(
            verify_consistency(0, 10, &[0u8; 32], &t.root(), &[]),
            Err(ProofError::RootMismatch { .. })
        ));
        assert!(matches!(
            verify_consistency(0, 10, &hash_empty(), &t.root(), &[hash_leaf(b"x")]),
            Err(ProofError::ExpectedEmpty { .. })
        ));
    }

    #[test]
    fn consistency_proof_sizes_are_logarithmic() {
        let t = tree(1024);
        for first in 1..=1024u64 {
            assert!(
                t.consistency_proof(first, 1024).unwrap().len() <= 11,
                "first={first}"
            );
        }
    }

    #[test]
    fn corrupted_consistency_nodes_are_rejected() {
        let t = tree(100);
        let (first, second) = (37u64, 100u64);
        let proof = t.consistency_proof(first, second).unwrap();
        for i in 0..proof.len() {
            let mut bad = proof.clone();
            bad[i][31] ^= 0x80;
            assert!(
                verify_consistency(first, second, &t.root_at(first), &t.root_at(second), &bad)
                    .is_err(),
                "node {i}"
            );
        }
    }
}
