#![cfg(test)]

use crate::{evm_runner::{EvmRunner, project_root}, MergeKeccak, NumberHash};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use ckb_merkle_mountain_range::{util::MemStore, MMR};
use proptest::{prop_assert, proptest};

sol! {
    struct MmrLeaf {
        uint256 index;
        bytes32 hash;
    }

    function CalculateRoot(bytes32[] proof, MmrLeaf[] leaves, uint256 leafCount) external pure returns (bytes32);
    function VerifyProof(bytes32 root, bytes32[] proof, MmrLeaf[] leaves, uint256 leafCount) external pure returns (bool);
}

fn solidity_calculate_root(
    runner: &mut EvmRunner,
    contract: alloy_primitives::Address,
    custom_leaves: Vec<(u32, [u8; 32])>,
    proof_items: Vec<Vec<u8>>,
    leaf_count: u64,
) -> [u8; 32] {
    let leaves: Vec<MmrLeaf> = custom_leaves
        .into_iter()
        .map(|(index, hash)| MmrLeaf {
            index: U256::from(index),
            hash: FixedBytes(hash),
        })
        .collect();

    let proof: Vec<FixedBytes<32>> = proof_items
        .into_iter()
        .map(|p| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&p);
            FixedBytes(bytes)
        })
        .collect();

    let call = CalculateRootCall {
        proof,
        leaves,
        leafCount: U256::from(leaf_count),
    };

    let result = runner.call_raw(contract, call.abi_encode());
    let decoded = CalculateRootCall::abi_decode_returns(&result, true).unwrap();
    decoded._0.0
}

fn test_mmr(runner: &mut EvmRunner, contract: alloy_primitives::Address, count: u32, mut proof_elem: Vec<u32>) {
    proof_elem.sort();
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);

    let positions: Vec<u64> =
        (0u32..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();

    let root = mmr.get_root().expect("get root");
    let proof = mmr
        .gen_proof(proof_elem.iter().map(|elem| positions[*elem as usize]).collect())
        .expect("gen proof");
    mmr.commit().expect("commit changes");

    let leaves = proof_elem
        .iter()
        .map(|elem| (positions[*elem as usize], NumberHash::from(*elem)))
        .collect::<Vec<_>>();
    let result = proof.verify(root.clone(), leaves.clone()).unwrap();
    assert!(result);

    let mut custom_leaves = leaves
        .into_iter()
        .zip(proof_elem.clone().into_iter())
        .map(|((_pos, leaf), index)| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&leaf.0);
            (index, hash)
        })
        .collect::<Vec<_>>();

    custom_leaves.dedup_by(|a, b| a.0 == b.0);
    custom_leaves.sort_by(|a, b| a.0.cmp(&b.0));

    let calculated = solidity_calculate_root(
        runner,
        contract,
        custom_leaves,
        proof.proof_items().to_vec().into_iter().map(|n| n.0).collect(),
        count as u64,
    );

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&root.0);
    assert_eq!(root_hash, calculated);
}

fn setup() -> (EvmRunner, alloy_primitives::Address) {
    let root = project_root();
    let mut runner = EvmRunner::new();
    let addr = runner.deploy(&root, "MerkleMountainRangeTest");
    (runner, addr)
}

#[test]
fn test_mmr_3_peaks() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![5]);
}

#[test]
fn test_mmr_2_peaks() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 10, vec![5]);
}

#[test]
fn test_mmr_1_peak() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 8, vec![5]);
}

#[test]
fn test_mmr_first_elem_proof() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![0]);
}

#[test]
fn test_mmr_last_elem_proof() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![10]);
}

#[test]
fn test_failing_case() {
    let (mut runner, addr) = setup();
    let elem = vec![
        85, 120, 113, 104, 109, 6, 101, 97, 41, 95, 15, 52, 19, 82, 33, 102, 114, 70, 53, 32, 107,
        65, 59, 80, 72, 36, 64, 22, 16, 38, 57, 106, 74, 76, 28, 81, 117, 83, 61, 122, 1, 12, 14,
        63, 20, 46, 4, 24, 111, 90, 2, 29, 126,
    ];
    test_mmr(&mut runner, addr, 127, elem);
}

#[test]
fn test_mmr_1_elem() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 1, vec![0]);
}

#[test]
fn test_mmr_2_elems() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 2, vec![0]);
    test_mmr(&mut runner, addr, 2, vec![1]);
}

#[test]
fn test_mmr_2_leaves_merkle_proof() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![3, 7]);
    test_mmr(&mut runner, addr, 11, vec![3, 4]);
}

#[test]
fn test_mmr_2_sibling_leaves_merkle_proof() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![4, 5]);
    test_mmr(&mut runner, addr, 11, vec![5, 6]);
    test_mmr(&mut runner, addr, 11, vec![6, 7]);
}

#[test]
fn test_mmr_3_leaves_merkle_proof() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 11, vec![4, 5, 6]);
    test_mmr(&mut runner, addr, 11, vec![3, 5, 7]);
    test_mmr(&mut runner, addr, 11, vec![3, 4, 5]);
    test_mmr(&mut runner, addr, 100, vec![3, 5, 13]);
}

#[test]
fn test_gen_proof_with_duplicate_leaves() {
    let (mut runner, addr) = setup();
    test_mmr(&mut runner, addr, 10, vec![5, 5]);
}

fn solidity_verify_proof(
    runner: &mut EvmRunner,
    contract: alloy_primitives::Address,
    root: [u8; 32],
    proof: Vec<FixedBytes<32>>,
    leaves: Vec<MmrLeaf>,
    leaf_count: u64,
) -> Result<bool, String> {
    let call = VerifyProofCall {
        root: FixedBytes(root),
        proof,
        leaves,
        leafCount: U256::from(leaf_count),
    };
    match runner.call_may_revert(contract, call.abi_encode()) {
        Ok(result) => {
            let decoded = VerifyProofCall::abi_decode_returns(&result, true)
                .map_err(|e| format!("decode error: {e}"))?;
            Ok(decoded._0)
        }
        Err(e) => Err(e),
    }
}

/// Build a valid MMR proof and return all the pieces needed for Solidity verification.
fn build_mmr_proof(count: u32, leaf_idx: u32) -> (
    [u8; 32],           // root
    Vec<FixedBytes<32>>, // proof items
    Vec<MmrLeaf>,       // leaves
    [u8; 32],           // leaf hash
) {
    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
    let positions: Vec<u64> = (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
    let root = mmr.get_root().unwrap();
    let proof = mmr.gen_proof(vec![positions[leaf_idx as usize]]).unwrap();
    mmr.commit().unwrap();

    let leaf = NumberHash::from(leaf_idx);
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&leaf.0);
    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&root.0);

    let sol_proof: Vec<FixedBytes<32>> = proof.proof_items().iter().map(|p| {
        let mut b = [0u8; 32]; b.copy_from_slice(&p.0); FixedBytes(b)
    }).collect();

    let sol_leaves = vec![MmrLeaf {
        index: U256::from(leaf_idx),
        hash: FixedBytes(leaf_hash),
    }];

    (root_hash, sol_proof, sol_leaves, leaf_hash)
}

proptest! {
    #[test]
    fn test_random_mmr(count in 10u32..500u32) {
        use rand::seq::SliceRandom;
        use rand::Rng;

        let mut leaves: Vec<u32> = (0..count).collect();
        let mut rng = rand::thread_rng();
        leaves.shuffle(&mut rng);
        let leaves_count = rng.gen_range(1..count - 1);
        leaves.truncate(leaves_count as usize);

        let (mut runner, addr) = setup();
        test_mmr(&mut runner, addr, count, leaves);
    }

    /// Corrupting a proof element must not verify.
    #[test]
    fn test_corrupt_proof_element(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        byte_idx in 0usize..32,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, mut sol_proof, sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        if sol_proof.is_empty() { return Ok(()); }
        sol_proof[0].0[byte_idx] ^= 0xff;

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "corrupted proof verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {} // revert is fine
        }
    }

    /// Corrupting the leaf hash must not verify.
    #[test]
    fn test_corrupt_leaf_hash(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        byte_idx in 0usize..32,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, mut sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        sol_leaves[0].hash.0[byte_idx] ^= 0xff;

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "forged leaf hash verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {}
        }
    }

    /// Wrong root must not verify.
    #[test]
    fn test_wrong_root(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        byte_idx in 0usize..32,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (mut root_hash, sol_proof, sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        root_hash[byte_idx] ^= 0xff;

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "wrong root verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {}
        }
    }

    /// Out-of-bounds leaf index must not verify.
    #[test]
    fn test_oob_leaf_index(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        offset in 1u64..256u64,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, mut sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        sol_leaves[0].index = U256::from(count as u64 + offset);

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "OOB leaf index verified for count={count}"),
            Err(_) => {}
        }
    }

    /// Random replacement hash must not verify.
    #[test]
    fn test_random_leaf_hash(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        fake_hash in proptest::array::uniform32(0u8..),
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, mut sol_leaves, real_hash) = build_mmr_proof(count, leaf_idx);

        if fake_hash == real_hash { return Ok(()); }
        sol_leaves[0].hash = FixedBytes(fake_hash);

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "random hash verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {}
        }
    }
}
