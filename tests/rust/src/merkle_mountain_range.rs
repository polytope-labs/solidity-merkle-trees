#![cfg(test)]

use crate::{
    evm_runner::{project_root, EvmRunner},
    MergeKeccak, NumberHash,
};
use ::merkle_mountain_range::{util::MemStore, MMR};
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::{sol, SolCall};
use proptest::{prop_assert, proptest, test_runner::Config as ProptestConfig};

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
        .map(|(index, hash)| MmrLeaf { index: U256::from(index), hash: FixedBytes(hash) })
        .collect();

    let proof: Vec<FixedBytes<32>> = proof_items
        .into_iter()
        .map(|p| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&p);
            FixedBytes(bytes)
        })
        .collect();

    let call = CalculateRootCall { proof, leaves, leafCount: U256::from(leaf_count) };

    let result = runner.call_raw(contract, call.abi_encode());
    let decoded = CalculateRootCall::abi_decode_returns(&result, true).unwrap();
    decoded._0.0
}

fn test_mmr(
    runner: &mut EvmRunner,
    contract: alloy_primitives::Address,
    count: u32,
    mut proof_elem: Vec<u32>,
) {
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
        },
        Err(e) => Err(e),
    }
}

/// Build a valid MMR proof and return all the pieces needed for Solidity verification.
fn build_mmr_proof(
    count: u32,
    leaf_idx: u32,
) -> (
    [u8; 32],            // root
    Vec<FixedBytes<32>>, // proof items
    Vec<MmrLeaf>,        // leaves
    [u8; 32],            // leaf hash
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

    let sol_proof: Vec<FixedBytes<32>> = proof
        .proof_items()
        .iter()
        .map(|p| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&p.0);
            FixedBytes(b)
        })
        .collect();

    let sol_leaves = vec![MmrLeaf { index: U256::from(leaf_idx), hash: FixedBytes(leaf_hash) }];

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

    /// Duplicate leaves with the same index must not verify.
    /// The verifier does not enforce uniqueness of leaf indices, so two leaves
    /// at the same index each consume a proof element independently and produce
    /// a bogus root.  This test confirms that the computed root never matches.
    #[test]
    fn test_duplicate_leaf_same_index(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, sol_leaves, _leaf_hash) = build_mmr_proof(count, leaf_idx);

        // Duplicate the leaf: same index, same hash
        let mut dup_leaves = sol_leaves.clone();
        dup_leaves.push(dup_leaves[0].clone());

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, dup_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "duplicate leaf (same hash) verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {} // revert is acceptable
        }
    }

    /// Duplicate leaves with the same index but different hashes must not verify.
    #[test]
    fn test_duplicate_leaf_same_index_different_hash(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        fake_hash in proptest::array::uniform32(0u8..),
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, sol_leaves, real_hash) = build_mmr_proof(count, leaf_idx);

        if fake_hash == real_hash { return Ok(()); }

        // Append a second leaf at the same index with a different hash
        let mut dup_leaves = sol_leaves.clone();
        dup_leaves.push(MmrLeaf { index: sol_leaves[0].index, hash: FixedBytes(fake_hash) });

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, dup_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "duplicate leaf (different hash) verified for count={count}, leaf={leaf_idx}"),
            Err(_) => {} // revert is acceptable
        }
    }

    /// Multiple duplicates of the same leaf index in a multi-proof context.
    #[test]
    fn test_multi_proof_with_duplicate_indices(
        count in 4u32..200u32,
        idx_a_raw in 0u32..200u32,
        idx_b_raw in 0u32..200u32,
    ) {
        let idx_a = idx_a_raw % count;
        let idx_b = idx_b_raw % count;

        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> = (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let root = mmr.get_root().unwrap();

        let mut proof_indices = vec![idx_a, idx_b];
        proof_indices.sort();
        proof_indices.dedup();

        let proof = mmr
            .gen_proof(proof_indices.iter().map(|&i| positions[i as usize]).collect())
            .unwrap();
        mmr.commit().unwrap();

        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&root.0);

        let sol_proof: Vec<FixedBytes<32>> = proof
            .proof_items()
            .iter()
            .map(|p| { let mut b = [0u8; 32]; b.copy_from_slice(&p.0); FixedBytes(b) })
            .collect();

        // Build leaves with a duplicated index: include idx_a twice
        let mut sol_leaves: Vec<MmrLeaf> = proof_indices.iter().map(|&i| {
            let leaf = NumberHash::from(i);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&leaf.0);
            MmrLeaf { index: U256::from(i), hash: FixedBytes(hash) }
        }).collect();

        // Duplicate the first leaf
        sol_leaves.push(sol_leaves[0].clone());
        sol_leaves.sort_by(|a, b| a.index.cmp(&b.index));

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "multi-proof with duplicate index verified for count={count}, indices=[{idx_a},{idx_b}]"),
            Err(_) => {} // revert is acceptable
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

// =====================================================================
// Soundness fuzz: constructive (structural) attacks on the leaves array.
//
// The corruption-pattern proptests above all hold `leaves.len()` constant
// and mutate one field. They cannot find forgeries that require *adding*
// or *reordering* leaves. This block fuzzes those structural moves at
// 10x the case count.
// =====================================================================
proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    /// Insert an arbitrary leaf at an arbitrary position in the leaves array
    /// of an otherwise-valid single-leaf proof. The proof was generated for
    /// the original leaves only; verification must fail or revert for ANY
    /// such insertion (whether the inserted leaf is a duplicate, OOB,
    /// genuine-but-extra, or pure forgery).
    #[test]
    fn fuzz_structural_leaf_insertion(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        extra_index in 0u64..400u64,
        extra_hash in proptest::array::uniform32(0u8..),
        insert_at in 0usize..16,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, sol_proof, sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        let mut adv_leaves = sol_leaves.clone();
        let extra = MmrLeaf { index: U256::from(extra_index), hash: FixedBytes(extra_hash) };
        let pos = insert_at.min(adv_leaves.len());
        adv_leaves.insert(pos, extra);

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, adv_leaves, count as u64) {
            Ok(verified) => prop_assert!(
                !verified,
                "structural insertion verified: count={count}, leaf={leaf_idx}, extra_idx={extra_index}, pos={pos}"
            ),
            Err(_) => {} // revert is the desired outcome
        }
    }

    /// Permute the leaves of a multi-leaf proof. The proof is order-sensitive;
    /// any permutation other than the strictly-sorted original must fail.
    #[test]
    fn fuzz_structural_leaf_permutation(
        count in 4u32..200u32,
        leaf_a_raw in 0u32..200u32,
        leaf_b_raw in 0u32..200u32,
        leaf_c_raw in 0u32..200u32,
    ) {
        use rand::seq::SliceRandom;

        let mut indices = vec![leaf_a_raw % count, leaf_b_raw % count, leaf_c_raw % count];
        indices.sort();
        indices.dedup();
        if indices.len() < 2 { return Ok(()); }

        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> = (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let root = mmr.get_root().unwrap();
        let proof = mmr.gen_proof(indices.iter().map(|&i| positions[i as usize]).collect()).unwrap();
        mmr.commit().unwrap();

        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&root.0);
        let sol_proof: Vec<FixedBytes<32>> = proof.proof_items().iter().map(|p| {
            let mut b = [0u8; 32]; b.copy_from_slice(&p.0); FixedBytes(b)
        }).collect();
        let mut sol_leaves: Vec<MmrLeaf> = indices.iter().map(|&i| {
            let leaf = NumberHash::from(i);
            let mut h = [0u8; 32]; h.copy_from_slice(&leaf.0);
            MmrLeaf { index: U256::from(i), hash: FixedBytes(h) }
        }).collect();

        // shuffle until different from sorted
        let original = sol_leaves.clone();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            sol_leaves.shuffle(&mut rng);
            if sol_leaves.iter().map(|l| l.index).collect::<Vec<_>>() !=
               original.iter().map(|l| l.index).collect::<Vec<_>>() { break; }
        }
        if sol_leaves.iter().map(|l| l.index).collect::<Vec<_>>() ==
           original.iter().map(|l| l.index).collect::<Vec<_>>() { return Ok(()); }

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "permuted leaves verified: count={count}, indices={indices:?}"),
            Err(_) => {}
        }
    }

    /// #2 — Permute the proof array. Proof order is load-bearing (elements
    /// are consumed sequentially during subtree traversal).
    #[test]
    fn fuzz_structural_proof_permutation(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
    ) {
        use rand::seq::SliceRandom;

        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, mut sol_proof, sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        if sol_proof.len() < 2 { return Ok(()); }

        let original = sol_proof.clone();
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            sol_proof.shuffle(&mut rng);
            if sol_proof != original { break; }
        }
        if sol_proof == original { return Ok(()); }

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "permuted proof verified: count={count}, leaf={leaf_idx}"),
            Err(_) => {}
        }
    }

    /// #2 — Drop one element from the proof. Must revert with ProofExhausted
    /// (or at worst fail verification).
    #[test]
    fn fuzz_structural_proof_truncation(
        count in 2u32..200u32,
        leaf_idx_raw in 0u32..200u32,
        drop_idx_raw in 0usize..16,
    ) {
        let leaf_idx = leaf_idx_raw % count;
        let (root_hash, mut sol_proof, sol_leaves, _) = build_mmr_proof(count, leaf_idx);

        if sol_proof.is_empty() { return Ok(()); }
        let drop_at = drop_idx_raw % sol_proof.len();
        sol_proof.remove(drop_at);

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "truncated proof verified: count={count}, leaf={leaf_idx}, dropped={drop_at}"),
            Err(_) => {}
        }
    }

    /// #6 — Metamorphic consistency. Proving A, B, A ∪ B, or A ∩ B against
    /// the same tree must all compute the same root. Catches bugs where
    /// proof shape or leaf partitioning affects the computed root.
    #[test]
    fn fuzz_metamorphic_overlapping_proofs(
        count in 4u32..100u32,
        a1 in 0u32..100u32,
        a2 in 0u32..100u32,
        b1 in 0u32..100u32,
        b2 in 0u32..100u32,
    ) {
        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> = (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let root = mmr.get_root().unwrap();

        let mut set_a: Vec<u32> = vec![a1 % count, a2 % count];
        let mut set_b: Vec<u32> = vec![b1 % count, b2 % count];
        set_a.sort(); set_a.dedup();
        set_b.sort(); set_b.dedup();

        let union: Vec<u32> = {
            let mut u: Vec<u32> = set_a.iter().chain(set_b.iter()).copied().collect();
            u.sort(); u.dedup(); u
        };
        let intersection: Vec<u32> = set_a.iter().filter(|i| set_b.contains(i)).copied().collect();

        let subsets: Vec<Vec<u32>> = [&set_a, &set_b, &union, &intersection]
            .into_iter().filter(|s| !s.is_empty()).cloned().collect();

        let mut root_hash = [0u8; 32]; root_hash.copy_from_slice(&root.0);

        let (mut runner, addr) = setup();
        for subset in subsets {
            let proof = mmr.gen_proof(subset.iter().map(|&i| positions[i as usize]).collect()).unwrap();
            let sol_proof: Vec<FixedBytes<32>> = proof.proof_items().iter().map(|p| {
                let mut b = [0u8; 32]; b.copy_from_slice(&p.0); FixedBytes(b)
            }).collect();
            let sol_leaves: Vec<MmrLeaf> = subset.iter().map(|&i| {
                let leaf = NumberHash::from(i);
                let mut h = [0u8; 32]; h.copy_from_slice(&leaf.0);
                MmrLeaf { index: U256::from(i), hash: FixedBytes(h) }
            }).collect();

            let verified = solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64)
                .expect("valid subset proof must not revert");
            prop_assert!(verified, "metamorphic subset {subset:?} failed to verify against root");
        }
        mmr.commit().unwrap();
    }

    /// Truncate one leaf from a multi-leaf proof. The proof was generated
    /// for the full set; with one leaf removed, the verifier must not
    /// produce the original root.
    #[test]
    fn fuzz_structural_leaf_truncation(
        count in 4u32..200u32,
        leaf_a_raw in 0u32..200u32,
        leaf_b_raw in 0u32..200u32,
        drop_idx in 0usize..3,
    ) {
        let mut indices = vec![leaf_a_raw % count, leaf_b_raw % count];
        indices.sort();
        indices.dedup();
        if indices.len() < 2 { return Ok(()); }

        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> = (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let root = mmr.get_root().unwrap();
        let proof = mmr.gen_proof(indices.iter().map(|&i| positions[i as usize]).collect()).unwrap();
        mmr.commit().unwrap();

        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&root.0);
        let sol_proof: Vec<FixedBytes<32>> = proof.proof_items().iter().map(|p| {
            let mut b = [0u8; 32]; b.copy_from_slice(&p.0); FixedBytes(b)
        }).collect();
        let mut sol_leaves: Vec<MmrLeaf> = indices.iter().map(|&i| {
            let leaf = NumberHash::from(i);
            let mut h = [0u8; 32]; h.copy_from_slice(&leaf.0);
            MmrLeaf { index: U256::from(i), hash: FixedBytes(h) }
        }).collect();

        let drop_at = drop_idx.min(sol_leaves.len() - 1);
        sol_leaves.remove(drop_at);

        let (mut runner, addr) = setup();
        match solidity_verify_proof(&mut runner, addr, root_hash, sol_proof, sol_leaves, count as u64) {
            Ok(verified) => prop_assert!(!verified, "truncated leaves verified: count={count}, indices={indices:?}, dropped={drop_at}"),
            Err(_) => {}
        }
    }
}

#[test]
fn test_mmr_gas_benchmark() {
    use rand::Rng;

    let (mut runner, contract) = setup();

    for count in [8u32, 32, 64, 128, 256, 512, 1024] {
        let store = MemStore::default();
        let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
        let positions: Vec<u64> =
            (0..count).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
        let root = mmr.get_root().unwrap();

        let threshold = std::cmp::max(1, count / 3);
        let mut rng = rand::thread_rng();
        let mut indices_set = std::collections::HashSet::new();
        while indices_set.len() < threshold as usize {
            indices_set.insert(rng.gen_range(0..count));
        }
        let mut indices: Vec<u32> = indices_set.into_iter().collect();
        indices.sort();

        let proof =
            mmr.gen_proof(indices.iter().map(|&i| positions[i as usize]).collect()).unwrap();
        mmr.commit().unwrap();

        let mut custom_leaves: Vec<(u32, [u8; 32])> = indices
            .iter()
            .map(|&i| {
                let leaf = NumberHash::from(i);
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&leaf.0);
                (i, hash)
            })
            .collect();
        custom_leaves.dedup_by(|a, b| a.0 == b.0);

        let sol_leaves: Vec<MmrLeaf> = custom_leaves
            .iter()
            .map(|&(idx, hash)| MmrLeaf { index: U256::from(idx), hash: FixedBytes(hash) })
            .collect();
        let sol_proof: Vec<FixedBytes<32>> = proof
            .proof_items()
            .iter()
            .map(|p| {
                let mut b = [0u8; 32];
                b.copy_from_slice(&p.0);
                FixedBytes(b)
            })
            .collect();

        let call = CalculateRootCall {
            proof: sol_proof.clone(),
            leaves: sol_leaves,
            leafCount: U256::from(count),
        };

        let (result, gas) = runner.call_with_gas(contract, call.abi_encode());
        let decoded = CalculateRootCall::abi_decode_returns(&result, true).unwrap();
        let mut root_hash = [0u8; 32];
        root_hash.copy_from_slice(&root.0);
        assert_eq!(decoded._0.0, root_hash);

        println!(
            "leaves={:>4}  proving={:>4}  proof_elements={:>4}  gas={:>8}",
            count,
            indices.len(),
            sol_proof.len(),
            gas
        );
    }
}
