#![cfg(test)]

use crate::{MergeKeccak, NumberHash, Token};
use ckb_merkle_mountain_range::{util::MemStore, MMR};
use forge_testsuite::{Contract, Runner};
use primitive_types::U256;
use proptest::{prop_compose, proptest};
use std::{env, path::PathBuf};

pub async fn solidity_calculate_root(
    contract: &mut Contract<'_>,
    custom_leaves: Vec<(u32, [u8; 32])>,
    proof_items: Vec<Vec<u8>>,
    leaf_count: u64,
) -> [u8; 32] {
    let token_leaves = custom_leaves
        .into_iter()
        .map(|(leaf_index, hash)| {
            Token::Tuple(vec![
                Token::Uint(U256::from(leaf_index)),
                Token::FixedBytes(hash.to_vec()),
            ])
        })
        .collect::<Vec<_>>();

    let nodes = proof_items.iter().map(|n| Token::FixedBytes(n.clone())).collect::<Vec<_>>();

    contract
        .call::<_, [u8; 32]>("CalculateRoot", (nodes, token_leaves, Token::Uint(leaf_count.into())))
        .await
        .unwrap()
}

pub async fn test_mmr(contract: &mut Contract<'_>, count: u32, mut proof_elem: Vec<u32>) {
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

    // simplified proof verification

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
        contract,
        custom_leaves,
        proof.proof_items().to_vec().into_iter().map(|n| n.0).collect(),
        count as u64,
    )
    .await;

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&root.0);
    assert_eq!(root_hash, calculated);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_3_peaks() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_peaks() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 10, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_1_peak() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 8, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_first_elem_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_last_elem_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![10]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_failing_case() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    let elem = vec![
        85, 120, 113, 104, 109, 6, 101, 97, 41, 95, 15, 52, 19, 82, 33, 102, 114, 70, 53, 32, 107,
        65, 59, 80, 72, 36, 64, 22, 16, 38, 57, 106, 74, 76, 28, 81, 117, 83, 61, 122, 1, 12, 14,
        63, 20, 46, 4, 24, 111, 90, 2, 29, 126,
    ];
    test_mmr(&mut contract, 127, elem).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_1_elem() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 1, vec![0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_elems() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 2, vec![0]).await;
    test_mmr(&mut contract, 2, vec![1]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_leaves_merkle_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![3, 7]).await;
    test_mmr(&mut contract, 11, vec![3, 4]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_sibling_leaves_merkle_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![4, 5]).await;
    test_mmr(&mut contract, 11, vec![5, 6]).await;
    test_mmr(&mut contract, 11, vec![6, 7]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_3_leaves_merkle_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 11, vec![4, 5, 6]).await;
    test_mmr(&mut contract, 11, vec![3, 5, 7]).await;
    test_mmr(&mut contract, 11, vec![3, 4, 5]).await;
    test_mmr(&mut contract, 100, vec![3, 5, 13]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gen_proof_with_duplicate_leaves() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMountainRangeTest").await;
    test_mmr(&mut contract, 10, vec![5, 5]).await;
}

prop_compose! {
    fn count_elem(count: u32)
                (elem in 0..count)
                -> (u32, u32) {
                    (count, elem)
    }
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
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
        let mut runner = Runner::new(PathBuf::from(&base_dir));
        runtime.block_on(async move {
            let mut contract = runner.deploy("MerkleMountainRangeTest").await;

            test_mmr(&mut contract, count, leaves).await;
        });
    }
}
