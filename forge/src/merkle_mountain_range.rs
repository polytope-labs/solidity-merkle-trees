#![cfg(test)]

use crate::{execute, runner, MergeKeccak, NumberHash, Token};
use ckb_merkle_mountain_range::{helper::{get_peaks, pos_height_in_tree}, mmr_position_to_k_index, util::MemStore, MMR, leaf_index_to_pos, leaf_index_to_mmr_size};
use hex_literal::hex;
use primitive_types::U256;

type MmrLeaf = (u64, u64, [u8; 32]);

#[test]
fn test_mmr_utils() {
    let mut runner = runner();

    let leading_zeros = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countLeadingZeros",
        (Token::Uint(U256::from(17))),
    )
    .unwrap();

    assert_eq!(leading_zeros.as_u32(), 17u64.leading_zeros());

    let count_zeros = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countZeroes",
        (Token::Uint(U256::from(17))),
    )
    .unwrap();

    assert_eq!(count_zeros.as_u32(), 17u64.count_zeros());

    let count_ones = execute::<_, U256>(
        &mut runner,
        "MerkleMountainRangeTest",
        "countOnes",
        (Token::Uint(U256::from(17))),
    )
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
        .unwrap();

        assert_eq!(result.0.len(), 6);
        assert_eq!(result.1.len(), 6);

        let result = execute::<_, (Vec<MmrLeaf>, Vec<MmrLeaf>)>(
            &mut runner,
            "MerkleMountainRangeTest",
            "leavesForPeak",
            (leaves, Token::Uint(U256::from(15))),
        )
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
                .unwrap();

            assert_eq!(peaks, leaf_index_to_mmr_size(pos));
        }
    }
}

#[test]
fn test_merkle_mountain_range() {
    let mut runner = runner();

    let store = MemStore::default();
    let mut mmr = MMR::<_, MergeKeccak, _>::new(0, &store);
    let positions: Vec<u64> = (0u32..=13).map(|i| mmr.push(NumberHash::from(i)).unwrap()).collect();
    let proof = mmr
        .gen_proof(vec![positions[2], positions[5], positions[8], positions[10], positions[12]])
        .unwrap();

    let leaves = vec![
        (NumberHash::from(2), positions[2]),
        (NumberHash::from(5), positions[5]),
        (NumberHash::from(8), positions[8]),
        (NumberHash::from(10), positions[10]),
        (NumberHash::from(12), positions[12]),
    ]
    .into_iter()
    .map(|(a, b)| (b, a))
    .collect::<Vec<_>>();

    let positions = leaves.iter().map(|(pos, _)| *pos).collect();
    let pos_with_index = mmr_position_to_k_index(positions, proof.mmr_size());

    let mut custom_leaves = pos_with_index
        .into_iter()
        .zip(leaves.clone())
        .map(|((pos, index), (_, leaf))| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&leaf.0);
            (pos, index, hash)
        })
        .collect::<Vec<_>>();

    custom_leaves.sort_by(|(a_pos, _, _), (b_pos, _, _)| a_pos.cmp(b_pos));

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

    let nodes = proof
        .proof_items()
        .iter()
        .map(|n| Token::FixedBytes(n.0.clone()))
        .collect::<Vec<_>>();

    let root = execute::<_, [u8; 32]>(
        &mut runner,
        "MerkleMountainRangeTest",
        "CalculateRoot",
        (nodes, token_leaves, Token::Uint(mmr.mmr_size().into())),
    )
    .unwrap();

    assert_eq!(root.to_vec(), mmr.get_root().unwrap().0);
}
