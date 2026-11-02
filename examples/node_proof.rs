// Prove intermediate node belongs to tree root
//
// Tree structure (16 leaves):
//
// Level 5:                    ROOT
//                            /    \
// Level 4:                 N4      N4'
//                         /  \    /   \
// Level 3:              N3   N3' N3'' N3'''
//                      / \   / \
// Level 2:           N0  N1 N2  N3  ...  ← Intermediate nodes
//                   /  \
// Level 1:        N10 N11 ...
//                / \  / \
// Level 0:      L0 L1 L2 L3 L4 ... L15    ← Leaves
//               ↑
//            Proving N0 (intermediate node) belongs to ROOT
//
// Proof path: N0 → N3 → N4 → ROOT
// Siblings needed: [N1, N3', N4']
//
// Key insight: We treat N0, N1, N2, N3 as "leaves" of a smaller tree
// Then verify using standard MerkleProof::verify()!

use ant_merkle::{algorithms::Sha256, Hasher, MerkleTree};

fn main() {
    // Build tree
    let leaves: Vec<[u8; 32]> = (0..16)
        .map(|i| Sha256::hash(format!("leaf_{}", i).as_bytes()))
        .collect();
    let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let root = tree.root().unwrap();

    // Get intermediate node at level 2
    let level = 2;
    let nodes = tree.get_nodes_at_level(level).unwrap();
    let (node_index, node_hash) = nodes[0];

    // Create proof (returns MerkleProof!)
    let proof = tree.proof_from_node(level, node_index).unwrap();

    // Verify (treat nodes at this level as "leaves")
    let relative_index = 0; // First node at this level
    let is_valid = proof.verify(root, &[relative_index], &[node_hash], nodes.len());

    assert!(is_valid);
    println!("✓ Node → Root proof verified successfully!");
}
