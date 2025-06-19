#![cfg(test)]

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

    let leaves = (0..1024).map(|_| H256::random().as_bytes().to_vec()).collect::<Vec<_>>();
    let leaf_hashes = leaves.iter().map(keccak256).collect::<Vec<[u8; 32]>>();

    let tree = MerkleTree::<Keccak256>::from_leaves(&leaf_hashes);

    let mut rng = rand::thread_rng();
    let mut indices = std::collections::HashSet::new();
    while indices.len() < 667 {
        indices.insert(rng.gen_range(0..1024usize));
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

    let calculated = contract
        .call::<_, [u8; 32]>("CalculateRoot", (args.clone(), leaves_with_indices))
        .await
        .unwrap();

    assert_eq!(tree.root().unwrap(), calculated);

    {
        {
            for i in [2usize, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048] {
                let calculated = contract
                    .call::<_, u32>("TreeHeight", (Token::Uint(Uint::from(i))))
                    .await
                    .unwrap();
                assert_eq!(calculated as u32, i.ilog2());
            }
        }

        let beefy_root =
            binary_merkle_tree::merkle_root::<sp_runtime::traits::Keccak256, _>(leaves.clone());

        assert_eq!(beefy_root, H256(calculated));
    }
}

fn tree_height(num_leaves: u64) -> u64 {
    let mut height = 0;
    let mut nodes = num_leaves;
    while nodes > 1 {
        height += 1;
        nodes = (nodes + 1) / 2;
    }
    height
}

fn optimized_hash(left: H256, right: H256) -> H256 {
    H256(keccak256(&[left.as_bytes(), right.as_bytes()].concat()))
}

pub fn calculate_balanced_root(
    proof: &[Node],
    leaves: &[Node],
    num_leaves: u64,
) -> Result<H256, String> {
    let mut p = 0;
    let mut f = 0;
    let mut h = tree_height(num_leaves);
    dbg!(h);
    let mut flattened = iter::repeat(Node::default())
        .take(2usize.pow((h - 1) as u32))
        .collect::<Vec<_>>();

    // Process leaves
    let mut l = 0;
    while l < leaves.len() {
        if leaves[l].position % 2 == 0 {
            if p < proof.len() && proof[p].position == leaves[l].position + 1 {
                // Next sibling is in proof
                let node = Node {
                    hash: optimized_hash(leaves[l].hash, proof[p].hash),
                    position: leaves[l].position / 2,
                };
                flattened[f] = node;
                f += 1;
                p += 1;
            } else if l + 1 < leaves.len() && leaves[l + 1].position == leaves[l].position + 1 {
                // Next sibling must be in leaves
                let node = Node {
                    hash: optimized_hash(leaves[l].hash, leaves[l + 1].hash),
                    position: leaves[l].position / 2,
                };
                flattened[f] = node;
                f += 1;
                l += 1;
            } else {
                let node = Node { hash: leaves[l].hash, position: leaves[l].position / 2 };
                flattened[f] = node;
                f += 1;
                l += 1;
            }
        } else {
            if p < proof.len() && proof[p].position == leaves[l].position - 1 {
                // Next sibling is in proof
                let node = Node {
                    hash: optimized_hash(proof[p].hash, leaves[l].hash),
                    position: proof[p].position / 2,
                };
                flattened[f] = node;
                f += 1;
                p += 1;
            } else if l + 1 < leaves.len() && leaves[l + 1].position == leaves[l].position - 1 {
                // Next sibling must be in leaves
                let node = Node {
                    hash: optimized_hash(leaves[l + 1].hash, leaves[l].hash),
                    position: leaves[l + 1].position / 2,
                };
                flattened[f] = node;
                f += 1;
                l += 1;
            } else {
                return Err(format!("{} Leaf missing left sibling node", leaves[l].position));
            }
        }
        l += 1;
    }

    // We've processed all leaves and are moving up the tree
    h -= 1;

    while flattened[0].position != 1 {
        let mut r = 0;
        let mut w = 0;

        while r < flattened.len() {
            if flattened[r].position == 0 ||
                flattened[r].position >= 2u64.pow((h + 1) as u32) as usize
            {
                // Moving on up
                if h != 0 {
                    h -= 1;
                }
                r = 0;
                w = 0;
                break;
            }

            if flattened[r].position % 2 == 0 {
                if p < proof.len() && proof[p].position == flattened[r].position + 1 {
                    // Next sibling is in proof
                    let node = Node {
                        hash: optimized_hash(flattened[r].hash, proof[p].hash),
                        position: flattened[r].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    p += 1;
                } else if r + 1 < flattened.len() &&
                    flattened[r + 1].position == flattened[r].position + 1
                {
                    // Next sibling must be in flattened
                    let node = Node {
                        hash: optimized_hash(flattened[r].hash, flattened[r + 1].hash),
                        position: flattened[r].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                } else {
                    let node =
                        Node { hash: flattened[r].hash, position: flattened[r].position / 2 };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                }
            } else {
                if p < proof.len() && proof[p].position == flattened[r].position - 1 {
                    // Next sibling is in proof
                    let node = Node {
                        hash: optimized_hash(proof[p].hash, flattened[r].hash),
                        position: proof[p].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    p += 1;
                } else if r + 1 < flattened.len() &&
                    flattened[r + 1].position == flattened[r].position - 1
                {
                    // Next sibling must be in flattened
                    let node = Node {
                        hash: optimized_hash(flattened[r + 1].hash, flattened[r].hash),
                        position: flattened[r + 1].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                } else {
                    return Err(
                        format!("Node {} missing left sibling node", flattened[r].position,),
                    );
                }
            }
            r += 1;
        }
    }

    Ok(flattened[0].hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_calculate_balanced_root() {
    let num_leaves = 600;
    let threshold = ((num_leaves * 1) / 3) - 1;
    // let threshold = 199;
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
