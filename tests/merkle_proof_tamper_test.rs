//! Negative tests: `MerkleProof::verify` must reject proofs that don't match the tree.
//!
//! Every case starts from a proof that verifies, changes exactly one input, and expects
//! `verify` to return `false` (never panic). Trees of 10 leaves (uneven layers) and
//! 16 leaves (a full tree) are both covered, because uneven layers take a different path.

use ant_merkle::{algorithms::Sha256, Hasher, MerkleProof, MerkleTree};

const SIZES: [usize; 2] = [10, 16];
const PROVEN: [usize; 2] = [3, 7];

fn leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| Sha256::hash(format!("leaf-{i}").as_bytes()))
        .collect()
}

struct Fixture {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    proof: MerkleProof<Sha256>,
    hashes: Vec<[u8; 32]>,
}

fn fixture(n: usize) -> Fixture {
    let leaves = leaves(n);
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().expect("non-empty tree has a root");
    let proof = tree.proof(&PROVEN);
    let hashes = PROVEN.iter().map(|&i| leaves[i]).collect();
    Fixture {
        leaves,
        root,
        proof,
        hashes,
    }
}

fn flip(mut hash: [u8; 32], byte: usize) -> [u8; 32] {
    hash[byte] ^= 0x01;
    hash
}

#[test]
fn untampered_proof_verifies() {
    for n in SIZES {
        let f = fixture(n);
        assert!(f.proof.verify(f.root, &PROVEN, &f.hashes, n), "n={}", n);
    }
}

#[test]
fn wrong_root_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        for byte in [0, 31] {
            let root = flip(f.root, byte);
            assert!(
                !f.proof.verify(root, &PROVEN, &f.hashes, n),
                "n={} byte={}",
                n,
                byte
            );
        }
    }
}

#[test]
fn tampered_proof_hash_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        let original = f.proof.proof_hashes().to_vec();
        assert!(!original.is_empty());
        for i in 0..original.len() {
            let mut hashes = original.clone();
            hashes[i] = flip(hashes[i], 0);
            let proof = MerkleProof::<Sha256>::new(hashes);
            assert!(
                !proof.verify(f.root, &PROVEN, &f.hashes, n),
                "n={} proof hash {}",
                n,
                i
            );
        }
    }
}

#[test]
fn wrong_leaf_hash_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        // A hash that isn't in the tree at all.
        let outsider = vec![Sha256::hash(b"not a leaf"), f.hashes[1]];
        assert!(
            !f.proof.verify(f.root, &PROVEN, &outsider, n),
            "n={} outsider",
            n
        );
        // A real leaf, but from a different position.
        let neighbour = vec![f.leaves[4], f.hashes[1]];
        assert!(
            !f.proof.verify(f.root, &PROVEN, &neighbour, n),
            "n={} neighbour",
            n
        );
        // One bit off.
        let flipped = vec![flip(f.hashes[0], 31), f.hashes[1]];
        assert!(
            !f.proof.verify(f.root, &PROVEN, &flipped, n),
            "n={} flipped",
            n
        );
    }
}

#[test]
fn wrong_leaf_index_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        // Indices swapped against their hashes.
        let swapped = [PROVEN[1], PROVEN[0]];
        assert!(
            !f.proof.verify(f.root, &swapped, &f.hashes, n),
            "n={} swapped",
            n
        );
        // Each index shifted by one, either way.
        for (a, b) in [(2, 7), (4, 7), (3, 6), (3, 8)] {
            assert!(
                !f.proof.verify(f.root, &[a, b], &f.hashes, n),
                "n={} [{}, {}]",
                n,
                a,
                b
            );
        }
    }
}

#[test]
fn out_of_range_or_duplicate_index_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        let tree = MerkleTree::<Sha256>::from_leaves(&f.leaves);
        let single = tree.proof(&[3]);
        assert!(single.verify(f.root, &[3], &[f.leaves[3]], n));
        for index in [n, n + 1, usize::MAX] {
            assert!(
                !single.verify(f.root, &[index], &[f.leaves[3]], n),
                "n={} index={}",
                n,
                index
            );
        }
        let duplicate = tree.proof(&[3, 3]);
        assert!(
            !duplicate.verify(f.root, &[3, 3], &[f.leaves[3], f.leaves[3]], n),
            "n={} duplicate",
            n
        );
    }
}

#[test]
fn truncated_or_empty_proof_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        let original = f.proof.proof_hashes().to_vec();
        let mut no_last = original.clone();
        no_last.pop();
        let no_first = original[1..].to_vec();
        for (name, hashes) in [
            ("no last", no_last),
            ("no first", no_first),
            ("empty", vec![]),
        ] {
            let proof = MerkleProof::<Sha256>::new(hashes);
            assert!(
                !proof.verify(f.root, &PROVEN, &f.hashes, n),
                "n={} {}",
                n,
                name
            );
        }
    }
}

#[test]
fn mismatched_or_missing_inputs_are_rejected() {
    for n in SIZES {
        let f = fixture(n);
        assert!(
            !f.proof.verify(f.root, &PROVEN, &f.hashes[..1], n),
            "n={} 2 indices, 1 hash",
            n
        );
        assert!(
            !f.proof.verify(f.root, &PROVEN[..1], &f.hashes, n),
            "n={} 1 index, 2 hashes",
            n
        );
        assert!(
            !f.proof.verify(f.root, &[], &[], n),
            "n={} nothing to prove",
            n
        );
        assert!(
            !f.proof.verify(f.root, &PROVEN, &f.hashes, 0),
            "n={} zero leaves",
            n
        );
    }
}

#[test]
fn proof_from_another_tree_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        let other: Vec<[u8; 32]> = (0..n)
            .map(|i| Sha256::hash(format!("other-{i}").as_bytes()))
            .collect();
        let other_proof = MerkleTree::<Sha256>::from_leaves(&other).proof(&PROVEN);
        assert!(
            !other_proof.verify(f.root, &PROVEN, &f.hashes, n),
            "n={}",
            n
        );
    }
}

#[test]
fn total_leaves_count_with_a_different_depth_is_rejected() {
    for n in SIZES {
        let f = fixture(n);
        // Both trees have depth 4; these counts give depth 3 or 5.
        for count in [1, 5, 8, 17, 32, usize::MAX] {
            assert!(
                !f.proof.verify(f.root, &PROVEN, &f.hashes, count),
                "n={} count={}",
                n,
                count
            );
        }
    }
}

#[test]
fn node_proof_rejects_wrong_position_hash_or_count() {
    let leaves = leaves(16);
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    let level = 2;
    let nodes = tree.get_nodes_at_level(level).unwrap();
    let (node_index, node_hash) = nodes[1];
    let proof = tree.proof_from_node(level, node_index).unwrap();

    assert!(proof.verify(root, &[1], &[node_hash], nodes.len()));
    assert!(
        !proof.verify(root, &[0], &[node_hash], nodes.len()),
        "wrong relative index"
    );
    assert!(
        !proof.verify(root, &[2], &[node_hash], nodes.len()),
        "wrong relative index"
    );
    assert!(
        !proof.verify(root, &[1], &[nodes[2].1], nodes.len()),
        "another node's hash"
    );
    assert!(
        !proof.verify(root, &[1], &[flip(node_hash, 0)], nodes.len()),
        "flipped hash"
    );
    assert!(
        !proof.verify(root, &[1], &[node_hash], leaves.len()),
        "leaf count, not node count"
    );
}

#[test]
fn proof_from_node_rejects_a_node_that_does_not_exist() {
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves(10));
    let depth = tree.depth();
    let nodes_at_1 = tree.get_nodes_at_level(1).unwrap().len();

    assert!(tree.proof_from_node(1, nodes_at_1 - 1).is_some());
    assert!(
        tree.proof_from_node(1, nodes_at_1).is_none(),
        "index past the level"
    );
    assert!(tree.proof_from_node(1, usize::MAX).is_none());
    assert!(tree.proof_from_node(depth, 0).is_some(), "the root itself");
    assert!(tree.proof_from_node(depth, 1).is_none());
    assert!(
        tree.proof_from_node(depth + 1, 0).is_none(),
        "level above the root"
    );
}

/// Two properties `verify` inherits from upstream rs-merkle. Neither lets a proof claim a
/// leaf that isn't in the tree, but a caller that treats the proof bytes or the leaf count
/// as authenticated must check them itself. These tests pin the behaviour so that any change
/// to it is deliberate.
mod not_bound_by_the_root {
    use super::*;

    /// The root doesn't commit to the number of leaves. Any count that gives the same tree
    /// depth, and the same proof layout for the proven indices, verifies.
    #[test]
    fn total_leaves_count_with_the_same_depth_still_verifies() {
        let f = fixture(10);
        for count in [9, 11, 12, 15, 16] {
            assert!(
                f.proof.verify(f.root, &PROVEN, &f.hashes, count),
                "count={}",
                count
            );
        }
    }

    /// `root` consumes only the proof hashes it needs, so extra hashes after them are
    /// ignored. Callers that need a canonical proof should check its length (evmlib checks
    /// it against the on-chain tree depth).
    #[test]
    fn trailing_proof_hashes_are_ignored() {
        let f = fixture(10);
        let mut hashes = f.proof.proof_hashes().to_vec();
        hashes.push([7u8; 32]);
        let padded = MerkleProof::<Sha256>::new(hashes);
        assert!(padded.verify(f.root, &PROVEN, &f.hashes, 10));
    }
}
