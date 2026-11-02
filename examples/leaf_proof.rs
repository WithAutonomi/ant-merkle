// Minimal example: Prove leaf belongs to tree root
//
// Tree structure (4 leaves):
//
//           ROOT
//          /    \
//        N1      N2
//       /  \    /  \
//      a    b  c    d
//              ↑
//           Proving this leaf belongs to ROOT
//
// Proof contains sibling hashes along the path from c → ROOT
// Path: c → N2 → ROOT
// Siblings needed: [b, N1]

use ant_merkle::{algorithms::Sha256, Hasher, MerkleTree};

fn main() {
    // Build tree
    let leaves: Vec<[u8; 32]> = ["a", "b", "c", "d"]
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap();
    println!("Root: {:?}", root);

    // Create proof for leaf at index 2 (leaf "c")
    let leaf_index = 2;
    let proof = tree.proof(&[leaf_index]);

    // Verify
    let is_valid = proof.verify(root, &[leaf_index], &[leaves[leaf_index]], leaves.len());

    assert!(is_valid);
    println!("✓ Leaf → Root proof verified successfully!");
}
