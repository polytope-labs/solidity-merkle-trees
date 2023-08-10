#![cfg(test)]

use crate::{
    execute,
    forge::{execute_single, single_runner},
    runner, MergeKeccak, NumberHash, Token,
};
use ckb_merkle_mountain_range::{
    helper::{get_peaks, pos_height_in_tree},
    leaf_index_to_mmr_size, leaf_index_to_pos, mmr_position_to_k_index,
    util::MemStore,
    MMR,
};
use forge::ContractRunner;
use foundry_evm::Address;
use hex_literal::hex;
use primitive_types::U256;
use proptest::{prop_compose, proptest};

type MmrLeaf = (u64, u64, [u8; 32]);

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_utils() {
    let mut runner = runner();

    let leading_zeros = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countLeadingZeros",
        (Token::Uint(U256::from(17))),
    )
    .await
    .unwrap();

    assert_eq!(leading_zeros.as_u32(), 17u64.leading_zeros());

    let count_zeros = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countZeroes",
        (Token::Uint(U256::from(17))),
    )
    .await
    .unwrap();

    assert_eq!(count_zeros.as_u32(), 17u64.count_zeros());

    let count_ones = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countOnes",
        (Token::Uint(U256::from(17))),
    )
    .await
    .unwrap();

    assert_eq!(count_ones.as_u32(), 17u64.count_ones());

    {
        for pos in [45, 98, 200, 412] {
            let height = execute::<_, U256>(
                &mut runner,
                "MerkleMountainRangeTest",
                "posToHeight",
                (Token::Uint(U256::from(pos))),
            )
            .await
            .unwrap();

            assert_eq!(height.as_u32(), pos_height_in_tree(pos));
        }
    }

    {
        let left = vec![3, 4].into_iter().map(|n| Token::Uint(U256::from(n))).collect();
        let right = vec![2, 5].into_iter().map(|n| Token::Uint(U256::from(n))).collect();

        let height = execute::<_, Vec<u64>>(
            &mut runner,
            "MerkleMountainRangeTest",
            "difference",
            (Token::Array(left), Token::Array(right)),
        )
        .await
        .unwrap();

        assert_eq!(height, vec![3, 4]);
    }

    {
        let indices =
            vec![2, 5].into_iter().map(|i| Token::Uint(U256::from(i))).collect::<Vec<_>>();
        let siblings = execute::<_, Vec<u64>>(
            &mut runner,
            "MerkleMountainRangeTest",
            "siblingIndices",
            (indices),
        )
        .await
        .unwrap();

        assert_eq!(siblings, vec![3, 4]);
    }

    {
        let leaves = vec![
            (3, 2, hex!("2b97a4b75a93aa1ac8581fac0f7d4ab42406569409a737bdf9de584903b372c5")),
            (8, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
            (14, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
            (22, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
            (25, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
            (30, 5, hex!("d279eb4bf22b2aeded31e65a126516215a9d93f83e3e425fdcd1a05ab347e535")),
        ]
        .into_iter()
        .map(|(pos, index, hash)| {
            Token::Tuple(vec![
                Token::Uint(U256::from(index)),
                Token::Uint(U256::from(pos)),
                Token::FixedBytes(hash.to_vec()),
            ])
        })
        .collect::<Vec<_>>();

        let result = execute::<_, (Vec<(u64, [u8; 32])>, Vec<u64>)>(
            &mut runner,
            "MerkleMountainRangeTest",
            "mmrLeafToNode",
            (leaves.clone()),
        )
        .await
        .unwrap();

        assert_eq!(result.0.len(), 6);
        assert_eq!(result.1.len(), 6);

        let result = execute::<_, (Vec<MmrLeaf>, Vec<MmrLeaf>)>(
            &mut runner,
            "MerkleMountainRangeTest",
            "leavesForPeak",
            (leaves, Token::Uint(U256::from(15))),
        )
        .await
        .unwrap();

        assert_eq!(result.0.len(), 3);
        assert_eq!(result.1.len(), 3);
    }

    {
        for pos in [45, 98, 200, 412] {
            let peaks = execute::<_, Vec<u64>>(
                &mut runner,
                "MerkleMountainRangeTest",
                "getPeaks",
                (Token::Uint(U256::from(pos))),
            )
            .await
            .unwrap();

            assert_eq!(peaks, get_peaks(pos));
        }
    }

    {
        for pos in [45, 98, 200, 412] {
            let peaks = execute::<_, u64>(
                &mut runner,
                "MerkleMountainRangeTest",
                "leafIndexToPos",
                (Token::Uint(U256::from(pos))),
            )
            .await
            .unwrap();

            assert_eq!(peaks, leaf_index_to_pos(pos));
        }
    }

    {
        for pos in [45, 98, 200, 412] {
            let peaks = execute::<_, u64>(
                &mut runner,
                "MerkleMountainRangeTest",
                "leafIndexToMmrSize",
                (Token::Uint(U256::from(pos))),
            )
            .await
            .unwrap();

            assert_eq!(peaks, leaf_index_to_mmr_size(pos));
        }
    }
}

pub fn solidity_calculate_root(
    contract: &mut ContractRunner,
    address: Address,
    custom_leaves: Vec<(u64, usize, [u8; 32])>,
    proof_items: Vec<Vec<u8>>,
    mmr_size: u64,
) -> [u8; 32] {
    let token_leaves = custom_leaves
        .into_iter()
        .map(|(pos, index, hash)| {
            Token::Tuple(vec![
                Token::Uint(U256::from(index)),
                Token::Uint(U256::from(pos)),
                Token::FixedBytes(hash.to_vec()),
            ])
        })
        .collect::<Vec<_>>();

    let nodes = proof_items.iter().map(|n| Token::FixedBytes(n.clone())).collect::<Vec<_>>();

    execute_single::<_, [u8; 32]>(
        contract,
        address,
        "CalculateRoot",
        (nodes, token_leaves, Token::Uint(mmr_size.into())),
    )
    .unwrap()
}

pub async fn test_mmr(count: u32, proof_elem: Vec<u32>) {
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
        .map(|(pos, leaf)| {
            let index = mmr_position_to_k_index(vec![pos], proof.mmr_size())[0].1;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&leaf.0);
            (pos, index, hash)
        })
        .collect::<Vec<_>>();

    custom_leaves.dedup_by(|a, b| a.0 == b.0);
    custom_leaves.sort_by(|a, b| a.0.cmp(&b.0));

    let mut runner = runner();
    let (mut contract, address) = single_runner(&mut runner, "MerkleMountainRangeTest").await;

    let calculated = solidity_calculate_root(
        &mut contract,
        address,
        custom_leaves,
        proof.proof_items().to_vec().into_iter().map(|n| n.0).collect(),
        proof.mmr_size(),
    );

    let mut root_hash = [0u8; 32];
    root_hash.copy_from_slice(&root.0);
    assert_eq!(root_hash, calculated);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_3_peaks() {
    test_mmr(11, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_peaks() {
    test_mmr(10, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_1_peak() {
    test_mmr(8, vec![5]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_first_elem_proof() {
    test_mmr(11, vec![0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_last_elem_proof() {
    test_mmr(11, vec![10]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_failing_case() {
    let elem = vec![
        85, 120, 113, 104, 109, 6, 101, 97, 41, 95, 15, 52, 19, 82, 33, 102, 114, 70, 53, 32, 107,
        65, 59, 80, 72, 36, 64, 22, 16, 38, 57, 106, 74, 76, 28, 81, 117, 83, 61, 122, 1, 12, 14,
        63, 20, 46, 4, 24, 111, 90, 2, 29, 126,
    ];
    test_mmr(127, elem).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_1_elem() {
    test_mmr(1, vec![0]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_elems() {
    test_mmr(2, vec![0]).await;
    test_mmr(2, vec![1]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_leaves_merkle_proof() {
    test_mmr(11, vec![3, 7]).await;
    test_mmr(11, vec![3, 4]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_2_sibling_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5]).await;
    test_mmr(11, vec![5, 6]).await;
    test_mmr(11, vec![6, 7]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_mmr_3_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5, 6]).await;
    test_mmr(11, vec![3, 5, 7]).await;
    test_mmr(11, vec![3, 4, 5]).await;
    test_mmr(100, vec![3, 5, 13]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gen_proof_with_duplicate_leaves() {
    test_mmr(10, vec![5, 5]).await;
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
        runtime.block_on(test_mmr(count, leaves));
    }
}
