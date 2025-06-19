#![cfg(test)]
#![allow(dead_code, unused_imports, unused_variables, unused_assignments)]

use crate::{keccak256, positional_merkle::*, Keccak256, Token};
use ethers::abi::{AbiEncode, Uint};
use forge_testsuite::Runner;
use primitive_types::{H256, U256};
use rand::Rng;
use rs_merkle::{merkelize_sorted, MerkleTree};
use std::{
    collections::{HashMap, HashSet},
    env, iter,
    path::PathBuf,
};

#[tokio::test(flavor = "multi_thread")]
async fn multi_merkle_proof() {
    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMultiProofTest").await;

    let num_leaves = 600;
    let threshold = ((num_leaves * 1) / 3) - 1;

    let leaves = (0..num_leaves).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    let leaf_hashes = leaves.iter().map(keccak256).collect::<Vec<[u8; 32]>>();

    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

    let mut rng = rand::thread_rng();
    let mut indices = std::collections::HashSet::new();
    while indices.len() < threshold {
        indices.insert(rng.gen_range(0..num_leaves));
    }
    let mut indices: Vec<usize> = indices.into_iter().collect();
    indices.sort();
    let leaves_with_indices = indices
        .iter()
        .map(|i| {
            Token::Tuple(vec![
                Token::Uint(U256::from(*i)),
                Token::FixedBytes(leaf_hashes[*i].to_vec()),
            ])
        })
        .collect::<Vec<_>>();

    let proof = tree.proof_2d(&indices);

    let args = proof
        .into_iter()
        .map(|layers| {
            let layers = layers
                .into_iter()
                .map(|(index, node)| {
                    Token::Tuple(vec![
                        Token::Uint(U256::from(index)),
                        Token::FixedBytes(node.to_vec()),
                    ])
                })
                .collect::<Vec<_>>();
            Token::Array(layers)
        })
        .collect::<Vec<_>>();

    // println!("Encoded: {:?}", hex::encode(&(args.clone(),
    // leaves_with_indices.clone()).encode()));

    let calculated = contract
        .call::<_, [u8; 32]>("CalculateRoot", (args.clone(), leaves_with_indices))
        .await
        .unwrap();

    assert_eq!(tree.root().unwrap(), calculated);

    let beefy_root =
        binary_merkle_tree::merkle_root::<sp_runtime::traits::Keccak256, _>(leaves.clone());

    assert_eq!(beefy_root, H256(calculated));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_calculate_balanced_root() {
    let num_leaves = 600;
    let threshold = ((num_leaves * 1) / 3) - 1;
    dbg!(threshold);
    let leaves = (0..num_leaves).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    dbg!(leaves.len());
    let leaf_hashes = leaves.iter().map(keccak256).collect::<Vec<[u8; 32]>>();

    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);
    let mut rng = rand::thread_rng();
    let mut indices = std::collections::HashSet::new();
    while indices.len() < threshold {
        indices.insert(rng.gen_range(0..num_leaves));
    }
    let indices: Vec<usize> = indices.into_iter().collect();

    let positional_tree =
        PositionalMerkleTree::new(&leaf_hashes.clone().into_iter().map(H256).collect::<Vec<_>>())
            .unwrap();

    dbg!(positional_tree.root());

    let mut proof_items = vec![];

    for mut i in positional_tree.generate_multi_proof(&indices).unwrap().into_iter().rev() {
        i.sort_by_key(|node| node.position);
        proof_items.extend_from_slice(&i);
    }

    dbg!(proof_items.len());
    let height = tree_height(leaves.len() as u64);
    dbg!(height);

    let mut proof_leaves = indices
        .iter()
        .map(|&i| Node {
            hash: H256(leaf_hashes[i]),
            position: (2usize.pow((height) as u32) + i) as usize,
        })
        .collect::<Vec<_>>();
    proof_leaves.sort_by_key(|node| node.position);

    let root = calculate_balanced_root(&proof_items, &proof_leaves, leaves.len() as u64).unwrap();

    dbg!(root);
    assert_eq!(root, H256(tree.root().unwrap()));

    let base_dir = env::current_dir().unwrap().parent().unwrap().display().to_string();
    let mut runner = Runner::new(PathBuf::from(&base_dir));
    let mut contract = runner.deploy("MerkleMultiProofTest").await;

    let abi_leaves = proof_leaves
        .iter()
        .map(|i| {
            Token::Tuple(vec![
                Token::Uint(U256::from(i.position)),
                Token::FixedBytes(i.hash.0.to_vec()),
            ])
        })
        .collect::<Vec<_>>();

    let abi_proof = proof_items
        .into_iter()
        .map(|node| {
            Token::Tuple(vec![
                Token::Uint(U256::from(node.position)),
                Token::FixedBytes(node.hash.0.to_vec()),
            ])
        })
        .collect::<Vec<_>>();

    let calculated = contract
        .call::<_, [u8; 32]>(
            "CalculateBalancedRoot",
            (abi_proof.clone(), abi_leaves.clone(), Token::Uint(U256::from(leaves.len()))),
        )
        .await
        .unwrap();

    dbg!(H256(calculated));

    // println!(
    //     "Encoded: {:?}",
    //     hex::encode(
    //         &(abi_proof.clone(), abi_leaves, Token::Uint(U256::from(leaves.len()))).encode()
    //     )
    // );

    assert_eq!(root, H256(calculated));
}
