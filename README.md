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

Supports both balanced and unbalanced trees (leaf count need not be a power of 2).

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.20;

import {MerkleMultiProof} from "@polytope-labs/solidity-merkle-trees/MerkleMultiProof.sol";

contract YourContract {
    function verify(
        bytes32 root,
        bytes32[] memory proof,
        MerkleMultiProof.Leaf[] memory leaves,
        uint256 leafCount
    ) public pure returns (bool) {
        return MerkleMultiProof.VerifyProof(root, proof, leaves, leafCount);
    }

    function calculateRoot(
        bytes32[] memory proof,
        MerkleMultiProof.Leaf[] memory leaves,
        uint256 leafCount
    ) public pure returns (bytes32) {
        return MerkleMultiProof.CalculateRoot(proof, leaves, leafCount);
    }
}
```

Leaves carry a 0-based `index` and `hash`. The proof is a flat `bytes32[]` array of sibling hashes — no position metadata needed. The contract converts indices to 1-based tree positions internally and walks up level by level, consuming proof elements for missing siblings.

You can generate the merkle multi proofs using the [rs-merkle](https://crates.io/crates/rs-merkle) crate.

To convert an `rs-merkle` proof into the format the Solidity verifier expects:

```rust
use rs_merkle::MerkleProof;

struct Leaf {
    index: usize,     // 0-based leaf index
    hash: [u8; 32],
}

fn convert_proof<T: Hasher<Hash = [u8; 32]>>(
    proof: &MerkleProof<T>,
    leaf_indices: &[usize],
    leaf_hashes: &[[u8; 32]],
) -> (Vec<[u8; 32]>, Vec<Leaf>) {
    // Proof hashes can be passed directly — they are already in the correct
    // consumption order (layer by layer, left to right).
    let proof_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let mut leaves: Vec<Leaf> = leaf_indices.iter().zip(leaf_hashes)
        .map(|(&i, &hash)| Leaf { index: i, hash })
        .collect();
    leaves.sort_by_key(|l| l.index);

    (proof_hashes, leaves)
}
```

## Merkle Mountain Range Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-mountain-range-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.20;

import {MerkleMountainRange} from "@polytope-labs/solidity-merkle-trees/MerkleMountainRange.sol";

contract YourContract {
    function verify(
        bytes32 root,
        bytes32[] memory proof,
        MerkleMountainRange.Leaf[] memory leaves,
        uint256 leafCount
    ) public pure returns (bool) {
        return MerkleMountainRange.VerifyProof(root, proof, leaves, leafCount);
    }

    function calculateRoot(
        bytes32[] memory proof,
        MerkleMountainRange.Leaf[] memory leaves,
        uint256 leafCount
    ) public pure returns (bytes32) {
        return MerkleMountainRange.CalculateRoot(proof, leaves, leafCount);
    }
}
```

You can generate the MMR proofs using the [ckb-merkle-mountain-range](https://crates.io/crates/ckb-merkle-mountain-range) crate.

> **Note:** The MMR verifier provides **membership** proofs only — it guarantees that a given leaf hash exists somewhere in the committed tree. It is **not positionally binding**: the `Leaf.index` field determines how the proof is reconstructed but a valid leaf hash may verify at more than one index. If your application requires positional binding, commit the leaf index into the leaf hash before inserting into the tree (e.g. `keccak256(abi.encodePacked(index, data))`).

## Merkle Patricia Trie

This library also supports the verification of the different styles of merkle patricia tries:

- [x] Substrate/Polkadot
- [x] Ethereum
- [ ] NEAR
      <br />

```solidity
pragma solidity ^0.8.20;

import {PolkadotTrie} from "@polytope-labs/solidity-merkle-trees/PolkadotTrie.sol";
import {EthereumTrie} from "@polytope-labs/solidity-merkle-trees/EthereumTrie.sol";
import {StorageValue} from "@polytope-labs/solidity-merkle-trees/trie/Node.sol";

contract YourContract {
    function verifyPolkadotProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public pure returns (PolkadotTrie.StorageValue[] memory) {
        // verifies proofs from state.getReadProof
        // returned StorageValue has: key, value, and keyPresent (to distinguish absent keys from empty values)
        return PolkadotTrie.VerifyProof(root, proof, keys);
    }

    function verifyPolkadotChildProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys,
        bytes memory childInfo
    ) public pure returns (PolkadotTrie.StorageValue[] memory) {
        // verifies child storage trie proofs
        return PolkadotTrie.ReadChildProof(root, proof, keys, childInfo);
    }

    function verifyEthereumProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) public pure returns (StorageValue[] memory) {
        // verifies ethereum specific merkle patricia proofs as described by EIP-1186.
        // can be used to verify the receipt trie, transaction trie and state trie
        return EthereumTrie.VerifyProof(root, proof, keys);
    }
}
```

## Testing Guide

This guide assumes [Rust](https://www.rust-lang.org/tools/install) (1.81.0+) along with its [nightly](https://rust-lang.github.io/rustup/concepts/channels.html#:~:text=it%20just%20run-,rustup%20toolchain%20install%20nightly,-%3A) version, [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), and [Foundry](https://github.com/foundry-rs/foundry) are installed.

Build the contracts:

```bash
forge build
```

Run the Solidity tests:

```bash
forge test -vvv
```

To run the Rust unit tests associated with the Merkle Multi Proof library:

```bash
cargo test --release --manifest-path=./tests/rust/Cargo.toml --lib merkle_multi_proof
```

To run the Rust unit tests associated with the Merkle Mountain Range library:

```bash
cargo test --release --manifest-path=./tests/rust/Cargo.toml --lib merkle_mountain_range
```

To run the Rust unit and fuzz tests associated with the Merkle Patricia Trie library:

```bash
cargo test --release --manifest-path=./tests/rust/Cargo.toml --lib merkle_patricia
cd tests/rust && cargo +nightly fuzz run trie_proof_valid
cargo +nightly fuzz run trie_proof_invalid
```

### Run Tests in Docker

Execute the following commands in the project directory:

```bash
git submodule update --init --recursive
# run tests for all merkle verifiers
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app rust:latest cargo test --release --manifest-path=./tests/rust/Cargo.toml
# fuzz the merkle-patricia verifier
docker build -t test .
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/tests/rust/fuzz test cargo +nightly fuzz run trie_proof_valid
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/tests/rust/fuzz test cargo +nightly fuzz run trie_proof_invalid
```

## License

This library is licensed under the [Apache 2.0 License](./LICENSE), Copyright (c) 2023 Polytope Labs.
