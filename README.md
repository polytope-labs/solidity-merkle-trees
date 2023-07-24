# `@polytope-labs/solidity-merkle-trees`

![Unit Tests](https://github.com/polytope-labs/solidity-merkle-trees/actions/workflows/test.yml/badge.svg)
[![NPM](https://img.shields.io/npm/v/@polytope-labs/solidity-merkle-trees?label=%40polytope-labs%2Fsolidity-merkle-trees)](https://www.npmjs.com/package/@polytope-labs/solidity-merkle-trees)

This library contains the implementations of various merkle tree verification algorithms. Currently supported algorithms:
<br />

- [x] Merkle Trees (supports unbalanced trees).
- [x] Merkle Mountain Ranges.
- [x] Merkle-Patricia Trie.

<img src="https://drive.google.com/uc?export=view&id=1aW_M8dULbPLNo4jTP2PsdNgW2UPST1jB"  style="max-width: 100%; height: auto;">

## Installation

```
npm install @polytope-labs/solidity-merkle-trees
```

## Merkle Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.0;

import "@polytope-labs/solidity-merkle-trees/MerkleMultiProof.sol";

contract YourContract {
    function verify(
        bytes32 root,
        Node[][] memory proof,
        Node[] leaves
    ) public {
        require(MerkleMultiProof.VerifyProof(root, proof, leaves), "Invalid proof");
    }
}
```

You can generate the 2D merkle multi proofs using this rust lib [polytope-labs/rs-merkle](https://github.com/polytope-labs/rs-merkle)

## Merkle Mountain Range Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-mountain-range-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.0;

import "@polytope-labs/solidity-merkle-trees/MerkleMountainRange.sol";

contract YourContract {
    function verify(
        bytes32 root,
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) public {
        require(MerkleMountainRange.VerifyProof(root, proof, leaves, mmrSize), "Invalid proof");
    }
}
```

You can derive the k-indices for the mmr leaves using this rust lib [polytope-labs/merkle-mountain-range](https://github.com/polytope-labs/merkle-mountain-range).

## Merkle Patricia Trie

This library also supports the verification of the different styles of merkle patricia tries:

- [x] Substrate
- [x] Ethereum
- [ ] NEAR
      <br />

```solidity
pragma solidity ^0.8.0;

import "@polytope-labs/solidity-merkle-trees/MerklePatricia.sol";

contract YourContract {
    function verifySubstrateProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys,
    ) public {
        bytes[] values = MerklePatricia.VerifySubstrateProof(root, proof, keys); // verifies proofs from state.getReadProof
        // do something with the verified values.
    }

    function verifyEthereumProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys,
    ) public {
        // verifies ethereum specific merkle patricia proofs as described by EIP-1188.
        // can be used to verify the receipt trie, transaction trie and state trie
        // contributed by @ripa1995
        bytes[] values = MerklePatricia.VerifyEthereumProof(root, proof, keys);
        // do something with the verified values.
      }
}
```

## Testing Guide

This guide assumes [Rust](https://www.rust-lang.org/tools/install)...along with it's [nightly](https://rust-lang.github.io/rustup/concepts/channels.html#:~:text=it%20just%20run-,rustup%20toolchain%20install%20nightly,-%3A) version, [Solidity](https://docs.soliditylang.org/en/v0.8.17/installing-solidity.html), [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and [Forge](https://github.com/foundry-rs/foundry/blob/master/README.md) are installed, if not browse the official websites/repositories for instructions.

Change into the forge directory and build the contracts;

```bash
cd forge
forge build
```

To run the unit tests associated with the Merkle Multi Proof library;

```bash
cargo test --lib merkle_multi_proof
```

To run the unit tests associated with the Merkle Mountain Range library;

```bash
cargo test --lib merkle_mountain_range
```

To run the unit and fuzz tests associated with the Merkle Patricia Trie library;

```bash
cargo test --lib merkle_patricia
cargo +nightly fuzz run trie_proof_valid
cargo +nightly fuzz run trie_proof_invalid
```

### Run Tests in Docker

Execute the following commands in the project directory:

```bash
git submodule update --init --recursive
# run tests for all merkle verifiers
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app rust:latest cargo test --release --manifest-path=./forge/Cargo.toml
# fuzz the merkle-patricia verifier
docker build -t test .
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/forge/fuzz test cargo +nightly fuzz run trie_proof_valid
docker run --memory="24g" --rm --user root -v "$PWD":/app -w /app/forge/fuzz test cargo +nightly fuzz run trie_proof_invalid

```

## License

This library is licensed under the [Apache 2.0 License](./LICENSE), Copyright (c) 2023 Polytope Labs.
