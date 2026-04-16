use crate::Keccak256;
use primitive_types::H256;
use rs_merkle::MerkleProof;

/// A leaf in the merkle tree with its 0-based index and hash value.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Leaf {
    pub hash: H256,
    pub index: usize,
}

/// The inputs needed to convert an rs-merkle proof into the flat format
/// expected by the Solidity MerkleMultiProof verifier.
pub struct RsMerkleProof<'a> {
    pub proof: &'a MerkleProof<Keccak256>,
    pub leaf_indices: &'a [usize],
    pub leaf_hashes: &'a [[u8; 32]],
}

/// The converted proof ready for Solidity consumption.
pub struct SolidityProof {
    pub proof_hashes: Vec<H256>,
    pub leaves: Vec<Leaf>,
}

impl<'a> From<RsMerkleProof<'a>> for SolidityProof {
    fn from(input: RsMerkleProof<'a>) -> Self {
        let proof_hashes = input.proof.proof_hashes().iter().map(|&h| H256(h)).collect();

        let mut leaves: Vec<Leaf> = input
            .leaf_indices
            .iter()
            .zip(input.leaf_hashes)
            .map(|(&i, hash)| Leaf { hash: H256(*hash), index: i })
            .collect();
        leaves.sort_by_key(|l| l.index);

        SolidityProof { proof_hashes, leaves }
    }
}
