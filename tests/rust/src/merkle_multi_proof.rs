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
use proptest::{
    prop_assert, prop_assert_eq, prop_assert_ne, proptest, test_runner::Config as ProptestConfig,
};
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

    /// Duplicate leaf with forged hash at the same index must not verify.
    /// The `while (positions[0] != 1)` short-circuit in `_walk` means the
    /// duplicate's climb is discarded. Padding the proof with `pad` between
    /// real sibling hashes lets the fake leaf consume "throwaway" siblings
    /// each level — without the fix, the real root is still returned.
    #[test]
    fn test_duplicate_leaf_forgery(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        fake_hash in proptest::array::uniform32(0u8..),
        pad in proptest::array::uniform32(0u8..),
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, real_hash) = build_multi_proof(num_leaves, leaf_idx);

        if fake_hash == real_hash { return Ok(()); }

        // Duplicate the leaf with a forged hash at the same index.
        sol_proof.leaves.push(Leaf { hash: H256(fake_hash), index: leaf_idx });

        // Interleave `pad` after each real proof element so the fake climb
        // has a "sibling" to consume at every level. Both leaves are at the
        // same position, so they traverse identical levels.
        let original = std::mem::take(&mut sol_proof.proof_hashes);
        for h in original {
            sol_proof.proof_hashes.push(h);
            sol_proof.proof_hashes.push(H256(pad));
        }

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "duplicate-leaf forgery verified for num_leaves={}, leaf_idx={}", num_leaves, leaf_idx),
            Err(_) => {} // revert is acceptable (desired post-fix behaviour)
        }
    }

    /// Duplicate leaf with the real hash is still malformed input — reject it.
    #[test]
    fn test_duplicate_leaf_same_hash(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        pad in proptest::array::uniform32(0u8..),
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, real_hash) = build_multi_proof(num_leaves, leaf_idx);

        sol_proof.leaves.push(Leaf { hash: H256(real_hash), index: leaf_idx });

        let original = std::mem::take(&mut sol_proof.proof_hashes);
        for h in original {
            sol_proof.proof_hashes.push(h);
            sol_proof.proof_hashes.push(H256(pad));
        }

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "duplicate-leaf (same hash) verified for num_leaves={}, leaf_idx={}", num_leaves, leaf_idx),
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

// =====================================================================
// Soundness fuzz: structural attacks on the leaves array.
// Same rationale as the MMR block — corruption-pattern tests miss
// insertions, permutations, and truncations.
// =====================================================================
proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    /// Insert an arbitrary leaf at an arbitrary position. Must fail or revert.
    #[test]
    fn fuzz_structural_leaf_insertion(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        extra_index in 0usize..400,
        extra_hash in proptest::array::uniform32(0u8..),
        insert_at in 0usize..16,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        let extra = Leaf { hash: H256(extra_hash), index: extra_index };
        let pos = insert_at.min(sol_proof.leaves.len());
        sol_proof.leaves.insert(pos, extra);

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(
                calc, root,
                "structural insertion verified: num_leaves={}, leaf={}, extra_idx={}, pos={}",
                num_leaves, leaf_idx, extra_index, pos
            ),
            Err(_) => {}
        }
    }

    /// #2 — Permute the proof. Sibling-consumption order is load-bearing.
    #[test]
    fn fuzz_structural_proof_permutation(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
    ) {
        use rand::seq::SliceRandom;

        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        if sol_proof.proof_hashes.len() < 2 { return Ok(()); }

        let original = sol_proof.proof_hashes.clone();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            sol_proof.proof_hashes.shuffle(&mut rng);
            if sol_proof.proof_hashes != original { break; }
        }
        if sol_proof.proof_hashes == original { return Ok(()); }

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(calc, root, "permuted proof matched root: num_leaves={}, leaf={}", num_leaves, leaf_idx),
            Err(_) => {}
        }
    }

    /// #2 — Drop a proof element. Must revert or fail verification.
    #[test]
    fn fuzz_structural_proof_truncation(
        num_leaves in 2usize..200,
        leaf_idx_raw in 0usize..200,
        drop_idx_raw in 0usize..16,
    ) {
        let leaf_idx = leaf_idx_raw % num_leaves;
        let (root, mut sol_proof, _) = build_multi_proof(num_leaves, leaf_idx);

        if sol_proof.proof_hashes.is_empty() { return Ok(()); }
        let drop_at = drop_idx_raw % sol_proof.proof_hashes.len();
        sol_proof.proof_hashes.remove(drop_at);

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(
                calc, root,
                "truncated proof matched root: num_leaves={}, leaf={}, dropped={}",
                num_leaves, leaf_idx, drop_at
            ),
            Err(_) => {}
        }
    }

    /// #6 — Metamorphic consistency. Proving A, B, A ∪ B, or A ∩ B against
    /// the same tree must all compute the same root.
    #[test]
    fn fuzz_metamorphic_overlapping_proofs(
        num_leaves in 4usize..100,
        a1 in 0usize..100,
        a2 in 0usize..100,
        b1 in 0usize..100,
        b2 in 0usize..100,
    ) {
        let leaf_hashes: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| keccak256(&(i as u32).to_le_bytes()).0).collect();
        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
        let root = tree.root().unwrap();

        let mut set_a: Vec<usize> = vec![a1 % num_leaves, a2 % num_leaves];
        let mut set_b: Vec<usize> = vec![b1 % num_leaves, b2 % num_leaves];
        set_a.sort(); set_a.dedup();
        set_b.sort(); set_b.dedup();

        let union: Vec<usize> = {
            let mut u: Vec<usize> = set_a.iter().chain(set_b.iter()).copied().collect();
            u.sort(); u.dedup(); u
        };
        let intersection: Vec<usize> = set_a.iter().filter(|i| set_b.contains(i)).copied().collect();

        let subsets: Vec<Vec<usize>> = [&set_a, &set_b, &union, &intersection]
            .into_iter().filter(|s| !s.is_empty()).cloned().collect();

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        for subset in subsets {
            let rs_proof = tree.proof(&subset);
            let leaves_vec: Vec<[u8; 32]> = subset.iter().map(|&i| leaf_hashes[i]).collect();
            let sol_proof = SolidityProof::from(RsMerkleProof {
                proof: &rs_proof,
                leaf_indices: &subset,
                leaf_hashes: &leaves_vec,
            });

            let calc = solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves)
                .expect("valid subset proof must not revert");
            prop_assert_eq!(calc, root, "metamorphic subset {:?} produced wrong root", subset);
        }
    }

    /// Truncate one leaf from a multi-leaf proof. Proof is for the full set;
    /// removing a leaf must not still verify.
    #[test]
    fn fuzz_structural_leaf_truncation(
        num_leaves in 4usize..200,
        leaf_a_raw in 0usize..200,
        leaf_b_raw in 0usize..200,
        drop_idx in 0usize..3,
    ) {
        let mut indices = vec![leaf_a_raw % num_leaves, leaf_b_raw % num_leaves];
        indices.sort();
        indices.dedup();
        if indices.len() < 2 { return Ok(()); }

        let leaf_hashes: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| keccak256(&(i as u32).to_le_bytes()).0).collect();
        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
        let root = tree.root().unwrap();
        let rs_proof = tree.proof(&indices);
        let leaves_vec: Vec<[u8; 32]> = indices.iter().map(|&i| leaf_hashes[i]).collect();
        let mut sol_proof = SolidityProof::from(RsMerkleProof {
            proof: &rs_proof,
            leaf_indices: &indices,
            leaf_hashes: &leaves_vec,
        });

        let drop_at = drop_idx.min(sol_proof.leaves.len() - 1);
        sol_proof.leaves.remove(drop_at);

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(
                calc, root,
                "truncated leaves verified: num_leaves={}, indices={:?}, dropped={}",
                num_leaves, indices, drop_at
            ),
            Err(_) => {}
        }
    }

    /// Permute the leaves of a multi-leaf proof. Order is load-bearing.
    #[test]
    fn fuzz_structural_leaf_permutation(
        num_leaves in 4usize..200,
        leaf_a_raw in 0usize..200,
        leaf_b_raw in 0usize..200,
        leaf_c_raw in 0usize..200,
    ) {
        use rand::seq::SliceRandom;

        let mut indices = vec![
            leaf_a_raw % num_leaves,
            leaf_b_raw % num_leaves,
            leaf_c_raw % num_leaves,
        ];
        indices.sort();
        indices.dedup();
        if indices.len() < 2 { return Ok(()); }

        let leaf_hashes: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| keccak256(&(i as u32).to_le_bytes()).0).collect();
        let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
        let root = tree.root().unwrap();
        let rs_proof = tree.proof(&indices);
        let leaves_vec: Vec<[u8; 32]> = indices.iter().map(|&i| leaf_hashes[i]).collect();
        let mut sol_proof = SolidityProof::from(RsMerkleProof {
            proof: &rs_proof,
            leaf_indices: &indices,
            leaf_hashes: &leaves_vec,
        });

        let original_indices: Vec<usize> = sol_proof.leaves.iter().map(|l| l.index).collect();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            sol_proof.leaves.shuffle(&mut rng);
            if sol_proof.leaves.iter().map(|l| l.index).collect::<Vec<_>>() != original_indices { break; }
        }
        if sol_proof.leaves.iter().map(|l| l.index).collect::<Vec<_>>() == original_indices { return Ok(()); }

        let project = project_root();
        let mut runner = EvmRunner::new();
        let contract = runner.deploy(&project, "MerkleMultiProofTest");

        match solidity_calc_root_raw(&mut runner, contract, &sol_proof, num_leaves) {
            Ok(calc) => prop_assert_ne!(
                calc, root,
                "permuted leaves verified: num_leaves={}, indices={:?}",
                num_leaves, indices
            ),
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
