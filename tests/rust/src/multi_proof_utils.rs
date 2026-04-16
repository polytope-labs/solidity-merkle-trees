use crate::Keccak256;
use primitive_types::H256;
use rs_merkle::{utils, MerkleProof};

/// A node in the merkle tree with its 1-based position and hash value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    pub hash: H256,
    pub position: usize,
}

/// ceil(log2(n)) — matches the Solidity `_ceilLog2` used by MerkleMultiProof.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Converts an rs-merkle `MerkleProof` into the positioned `Node` format
/// expected by the Solidity `MerkleMultiProof` verifier.
///
/// Returns `(proof_nodes, leaf_nodes)` both sorted by position.
pub fn convert_rs_merkle_proof(
    proof: &MerkleProof<Keccak256>,
    leaf_indices: &[usize],
    leaf_hashes: &[[u8; 32]],
    total_leaves: usize,
) -> (Vec<Node>, Vec<Node>) {
    let sol_height = ceil_log2(total_leaves);

    let proof_nodes = utils::indices::proof_indices_by_layers(leaf_indices, total_leaves)
        .into_iter()
        .enumerate()
        .flat_map(|(layer, indices)| {
            let level_start = 1usize << (sol_height - layer);
            indices.into_iter().map(move |idx| level_start + idx)
        })
        .zip(proof.proof_hashes())
        .map(|(position, &hash)| Node { hash: H256(hash), position })
        .collect();

    let first_leaf_pos = 1usize << sol_height;
    let mut leaf_nodes: Vec<Node> = leaf_indices
        .iter()
        .zip(leaf_hashes)
        .map(|(&i, hash)| Node { hash: H256(*hash), position: first_leaf_pos + i })
        .collect();
    leaf_nodes.sort_by_key(|n| n.position);

    (proof_nodes, leaf_nodes)
}
