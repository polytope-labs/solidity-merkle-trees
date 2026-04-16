#![cfg(test)]
#![allow(dead_code, unused_imports)]

use crate::{
    evm_runner::{project_root, EvmRunner},
    multi_proof_utils::{Leaf, RsMerkleProof, SolidityProof},
    Keccak256,
};
use alloy_primitives::{keccak256, FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use primitive_types::H256;
use proptest::{prop_assert, prop_assert_eq, prop_assert_ne, proptest};
use rand::Rng;
use rs_merkle::MerkleTree;
use std::collections::HashSet;

sol! {
    struct MpLeaf {
        uint256 index;
        bytes32 hash;
    }

    function CalculateRoot(bytes32[] proof, MpLeaf[] leaves, uint256 numLeaves) external view returns (bytes32);
}

fn leaves_to_abi(leaves: &[Leaf]) -> Vec<MpLeaf> {
    leaves
        .iter()
        .map(|l| MpLeaf { index: U256::from(l.index), hash: FixedBytes(l.hash.0) })
        .collect()
}

fn proof_to_abi(proof_hashes: &[H256]) -> Vec<FixedBytes<32>> {
    proof_hashes.iter().map(|h| FixedBytes(h.0)).collect()
}

fn solidity_calculate_root(
    runner: &mut EvmRunner,
    contract: alloy_primitives::Address,
    proof: &SolidityProof,
    num_leaves: usize,
) -> H256 {
    let call = CalculateRootCall {
        proof: proof_to_abi(&proof.proof_hashes),
        leaves: leaves_to_abi(&proof.leaves),
        numLeaves: U256::from(num_leaves),
    };

    let result = runner.call_raw(contract, call.abi_encode());
    let decoded = CalculateRootCall::abi_decode_returns(&result, true).unwrap();
    H256(decoded._0.0)
}

fn solidity_calc_root_raw(
    runner: &mut EvmRunner,
    contract: alloy_primitives::Address,
    proof: &SolidityProof,
    num_leaves: usize,
) -> Result<[u8; 32], String> {
    let call = CalculateRootCall {
        proof: proof_to_abi(&proof.proof_hashes),
        leaves: leaves_to_abi(&proof.leaves),
        numLeaves: U256::from(num_leaves),
    };
    match runner.call_may_revert(contract, call.abi_encode()) {
        Ok(result) => {
            let decoded = CalculateRootCall::abi_decode_returns(&result, true)
                .map_err(|e| format!("decode: {e}"))?;
            Ok(decoded._0.0)
        },
        Err(e) => Err(e),
    }
}

#[test]
fn test_calculate_root() {
    let num_leaves = 600;
    let threshold = ((num_leaves * 1) / 3) - 1;
    let leaves = (0..num_leaves).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    let leaf_hashes = leaves.iter().map(|l| keccak256(l).0).collect::<Vec<[u8; 32]>>();

    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
    let mut rng = rand::thread_rng();
    let mut indices = HashSet::new();
    while indices.len() < threshold {
        indices.insert(rng.gen_range(0..num_leaves));
    }
    let mut indices: Vec<usize> = indices.into_iter().collect();
    indices.sort();

    let rs_proof = tree.proof(&indices);
    let leaves_to_prove: Vec<[u8; 32]> = indices.iter().map(|&i| leaf_hashes[i]).collect();

    assert!(rs_proof.verify(tree.root().unwrap(), &indices, &leaves_to_prove, num_leaves));

    let sol_proof = SolidityProof::from(RsMerkleProof {
        proof: &rs_proof,
        leaf_indices: &indices,
        leaf_hashes: &leaves_to_prove,
    });

    let project = project_root();
    let mut runner = EvmRunner::new();
    let contract = runner.deploy(&project, "MerkleMultiProofTest");

    let calculated = solidity_calculate_root(&mut runner, contract, &sol_proof, leaves.len());

    assert_eq!(H256(tree.root().unwrap()), calculated);

    let beefy_root =
        binary_merkle_tree::merkle_root::<sp_runtime::traits::Keccak256, _>(leaves.clone());
    assert_eq!(beefy_root, calculated);
}

#[test]
fn test_rs_merkle_proof_conversion() {
    let num_leaves = 600;
    let threshold = ((num_leaves * 1) / 3) - 1;
    let leaves = (0..num_leaves).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    let leaf_hashes = leaves.iter().map(|l| keccak256(l).0).collect::<Vec<[u8; 32]>>();

    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

    let mut rng = rand::thread_rng();
    let mut indices_set = HashSet::new();
    while indices_set.len() < threshold {
        indices_set.insert(rng.gen_range(0..num_leaves));
    }
    let mut indices: Vec<usize> = indices_set.into_iter().collect();
    indices.sort();

    let rs_proof = tree.proof(&indices);
    let leaves_to_prove: Vec<[u8; 32]> = indices.iter().map(|&i| leaf_hashes[i]).collect();

    assert!(rs_proof.verify(tree.root().unwrap(), &indices, &leaves_to_prove, num_leaves));

    let sol_proof = SolidityProof::from(RsMerkleProof {
        proof: &rs_proof,
        leaf_indices: &indices,
        leaf_hashes: &leaves_to_prove,
    });

    let project = project_root();
    let mut runner = EvmRunner::new();
    let contract = runner.deploy(&project, "MerkleMultiProofTest");

    let calculated = solidity_calculate_root(&mut runner, contract, &sol_proof, num_leaves);

    assert_eq!(H256(tree.root().unwrap()), calculated);
}

/// Build a tree and single-leaf proof, return everything needed for Solidity verification.
fn build_multi_proof(
    num_leaves: usize,
    leaf_idx: usize,
) -> (
    [u8; 32],      // root
    SolidityProof, // converted proof
    [u8; 32],      // leaf hash
) {
    let leaf_hashes: Vec<[u8; 32]> =
        (0..num_leaves).map(|i| keccak256(&(i as u32).to_le_bytes()).0).collect();
    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
    let root = tree.root().unwrap();

    let proof = tree.proof(&[leaf_idx]);
    let sol_proof = SolidityProof::from(RsMerkleProof {
        proof: &proof,
        leaf_indices: &[leaf_idx],
        leaf_hashes: &[leaf_hashes[leaf_idx]],
    });

    (root, sol_proof, leaf_hashes[leaf_idx])
}

proptest! {
    /// Random tree sizes and leaf selections must produce matching roots.
    #[test]
    fn test_random_multi_proof(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        let calculated = solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves)
            .expect("CalculateRoot should not revert for valid proof");
        prop_assert_eq!(calculated, root);
    }

    /// Corrupted proof hash must produce different root.
    #[test]
    fn test_corrupt_proof_node(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        byte_idx in 0usize..32,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        if sol_proof.proof_hashes.is_empty() { return Ok(()); }
        sol_proof.proof_hashes[0].0[byte_idx] ^= 0xff;

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "corrupted proof matched root"),
            Err(_) => {} // revert is fine
        }
    }

    /// Corrupted leaf hash must produce different root.
    #[test]
    fn test_corrupt_leaf_hash(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        byte_idx in 0usize..32,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        sol_proof.leaves[0].hash.0[byte_idx] ^= 0xff;

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "forged leaf hash matched root"),
            Err(_) => {}
        }
    }

    /// Random replacement hash must produce different root.
    #[test]
    fn test_random_leaf_hash(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        fake_hash in proptest::array::uniform32(0u8..),
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, real_hash) = build_multi_proof(num_leaves, leaf_idx);

        if fake_hash == real_hash { return Ok(()); }
        sol_proof.leaves[0].hash = H256(fake_hash);

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "random hash matched root"),
            Err(_) => {}
        }
    }

    /// OOB leaf index must not produce matching root.
    #[test]
    fn test_oob_leaf_index(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        offset in 1usize..256,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        sol_proof.leaves[0].index = num_leaves + offset;

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "OOB index matched root"),
            Err(_) => {}
        }
    }

    /// Shifted leaf index must not produce matching root.
    #[test]
    fn test_shifted_leaf_index(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        delta in 1usize..5,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        let real_idx = sol_proof.leaves[0].index;
        let new_idx = if real_idx > delta { real_idx - delta } else { real_idx + delta };
        if new_idx == real_idx { return Ok(()); }
        sol_proof.leaves[0].index = new_idx;

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "shifted index matched root"),
            Err(_) => {}
        }
    }
}

#[test]
fn test_gas_benchmark() {
    let project = project_root();
    let mut runner = EvmRunner::new();
    let contract = runner.deploy(&project, "MerkleMultiProofTest");

    for num_leaves in [8, 32, 64, 128, 256, 512, 1024] {
        let leaf_hashes: Vec<[u8; 32]> =
            (0..num_leaves).map(|i| keccak256(&(i as u32).to_le_bytes()).0).collect();
        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

        // Prove ~1/3 of leaves
        let threshold = std::cmp::max(1, num_leaves / 3);
        let mut rng = rand::thread_rng();
        let mut indices_set = HashSet::new();
        while indices_set.len() < threshold {
            indices_set.insert(rng.gen_range(0..num_leaves));
        }
        let mut indices: Vec<usize> = indices_set.into_iter().collect();
        indices.sort();

        let rs_proof = tree.proof(&indices);
        let leaves_to_prove: Vec<[u8; 32]> = indices.iter().map(|&i| leaf_hashes[i]).collect();

        let sol_proof = SolidityProof::from(RsMerkleProof {
            proof: &rs_proof,
            leaf_indices: &indices,
            leaf_hashes: &leaves_to_prove,
        });

        let call = CalculateRootCall {
            proof: proof_to_abi(&sol_proof.proof_hashes),
            leaves: leaves_to_abi(&sol_proof.leaves),
            numLeaves: U256::from(num_leaves),
        };

        let (result, gas) = runner.call_with_gas(contract, call.abi_encode());
        let decoded = CalculateRootCall::abi_decode_returns(&result, true).unwrap();
        assert_eq!(decoded._0.0, tree.root().unwrap());

        println!(
            "leaves={:>4}  proving={:>4}  proof_elements={:>4}  gas={:>8}",
            num_leaves,
            indices.len(),
            sol_proof.proof_hashes.len(),
            gas
        );
    }
}
