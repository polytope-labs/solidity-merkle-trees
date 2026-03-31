# `@polytope-labs/solidity-merkle-trees`

![Unit Tests](https://github.com/polytope-labs/solidity-merkle-trees/actions/workflows/test.yml/badge.svg)
[![NPM](https://img.shields.io/npm/v/@polytope-labs/solidity-merkle-trees?label=%40polytope-labs%2Fsolidity-merkle-trees)](https://www.npmjs.com/package/@polytope-labs/solidity-merkle-trees)

<img src="assets/web3 foundation_grants_badge_white.png"  style="max-width: 100%; height: auto; max-height: 20em">

This library contains the implementations of various merkle tree verification algorithms. Currently supported algorithms:
<br />

- [x] Merkle Trees (supports unbalanced trees).
- [x] Merkle Mountain Ranges.
- [x] Merkle-Patricia Trie.


## Installation

```
npm install @polytope-labs/solidity-merkle-trees
```

## Merkle Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.17;

import "@polytope-labs/solidity-merkle-trees/MerkleMultiProof.sol";

contract YourContract {
    function verify(
        bytes32 root,
        MerkleMultiProof.Node[] memory proof,
        MerkleMultiProof.Node[] memory leaves,
        uint256 leafCount
    ) public {
        require(MerkleMultiProof.VerifyProof(root, proof, leaves, leafCount), "Invalid proof");
    }
}
```

You can generate the merkle multi proofs using the [rs-merkle](https://crates.io/crates/rs-merkle) crate.

The `Node.position` uses a 1-based indexing scheme where the root is `1` and the children of node `i` are `2i` and `2i+1`:

```
         1            <- root
       /   \
      2     3
     / \   / \
    4   5 6   7       <- leaves (leaf_count = 4, so leaf 0 → position 4, leaf 1 → 5, …)
```

To convert an `rs-merkle` proof into the positioned format the Solidity verifier expects:

```rust
use rs_merkle::{MerkleTree, MerkleProof, Hasher, utils};

struct Node {
    position: usize,
    hash: [u8; 32],
}

fn convert_proof<T: Hasher<Hash = [u8; 32]>>(
    proof: &MerkleProof<T>,
    leaf_indices: &[usize],
    leaf_hashes: &[[u8; 32]],
    total_leaves: usize,
) -> (Vec<Node>, Vec<Node>) {
    let height = utils::indices::tree_depth(total_leaves);

    // Calculate the expected proof node positions and zip with the proof hashes.
    // proof_indices_by_layers returns the 0-based indices that each proof hash
    // corresponds to, layer by layer (bottom-to-top), in the same order as proof_hashes().
    let proof_nodes = utils::indices::proof_indices_by_layers(leaf_indices, total_leaves)
        .into_iter()
        .enumerate()
        .flat_map(|(layer, indices)| {
            // At layer k (0 = leaves), 0-based index i → 1-based position:
            let level_start = 1usize << (height - layer);
            indices.into_iter().map(move |idx| level_start + idx)
        })
        .zip(proof.proof_hashes())
        .map(|(position, &hash)| Node { position, hash })
        .collect();

    let first_leaf_pos = 1usize << height;
    let mut leaf_nodes: Vec<Node> = leaf_indices
        .iter()
        .zip(leaf_hashes)
        .map(|(&i, &hash)| Node { position: first_leaf_pos + i, hash })
        .collect();
    leaf_nodes.sort_by_key(|n| n.position);

    (proof_nodes, leaf_nodes)
}
```

## Merkle Mountain Range Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-mountain-range-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.17;

import "@polytope-labs/solidity-merkle-trees/MerkleMountainRange.sol";

contract YourContract {
    function verify(
        bytes32 root,
        bytes32[] memory proof,
        MerkleMountainRange.Leaf[] memory leaves,
        uint256 leafCount
    ) public {
        require(MerkleMountainRange.VerifyProof(root, proof, leaves, leafCount), "Invalid proof");
    }
}
```

You can generate the MMR proofs using the [ckb-merkle-mountain-range](https://crates.io/crates/ckb-merkle-mountain-range) crate.

## Merkle Patricia Trie

This library also supports the verification of the different styles of merkle patricia tries:

- [x] Substrate
- [x] Ethereum
- [ ] NEAR
      <br />

```solidity
pragma solidity ^0.8.17;

import "@polytope-labs/solidity-merkle-trees/MerklePatricia.sol";

contract YourContract {
    function verifySubstrateProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public {
        // verifies proofs from state.getReadProof
        MerklePatricia.StorageValue[] memory values = MerklePatricia.VerifySubstrateProof(root, proof, keys);
        // do something with the verified values (values[i].key, values[i].value).
    }

    function verifyEthereumProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public {
        // verifies ethereum specific merkle patricia proofs as described by EIP-1188.
        // can be used to verify the receipt trie, transaction trie and state trie
        MerklePatricia.StorageValue[] memory values = MerklePatricia.VerifyEthereumProof(root, proof, keys);
        // do something with the verified values (values[i].key, values[i].value).
    }
}
```

## Testing Guide

This guide assumes [Rust](https://www.rust-lang.org/tools/install)...along with its [nightly](https://rust-lang.github.io/rustup/concepts/channels.html#:~:text=it%20just%20run-,rustup%20toolchain%20install%20nightly,-%3A) version, [Solidity](https://docs.soliditylang.org/en/v0.8.17/installing-solidity.html), [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and [Forge](https://github.com/foundry-rs/foundry/blob/master/README.md) are installed, if not browse the official websites/repositories for instructions.

Build the contracts;

```bash
forge build
```

To run the unit tests associated with the Merkle Multi Proof library;

```bash
cargo test --release --manifest-path=./integration-tests/Cargo.toml --lib merkle_multi_proof
```

To run the unit tests associated with the Merkle Mountain Range library;

```bash
cargo test --release --manifest-path=./integration-tests/Cargo.toml --lib merkle_mountain_range
```

To run the unit and fuzz tests associated with the Merkle Patricia Trie library;

```bash
cargo test --release --manifest-path=./integration-tests/Cargo.toml --lib merkle_patricia
cd integration-tests && cargo +nightly fuzz run trie_proof_valid
cargo +nightly fuzz run trie_proof_invalid
```

### Run Tests in Docker

Execute the following commands in the project directory:

```bash
git submodule update --init --recursive
# run tests for all merkle verifiers
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app rust:latest cargo test --release --manifest-path=./integration-tests/Cargo.toml
# fuzz the merkle-patricia verifier
docker build -t test .
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/integration-tests/fuzz test cargo +nightly fuzz run trie_proof_valid
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/integration-tests/fuzz test cargo +nightly fuzz run trie_proof_invalid
```

## License

This library is licensed under the [Apache 2.0 License](./LICENSE), Copyright (c) 2023 Polytope Labs.
