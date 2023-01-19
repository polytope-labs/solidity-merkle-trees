# `@polytope-labs/solidity-merkle-trees`

![Unit Tests](https://github.com/polytope-labs/solidity-merkle-trees/actions/workflows/test.yml/badge.svg)
[![NPM](https://img.shields.io/npm/v/@polytope-labs/solidity-merkle-trees?label=%40polytope-labs%2Fsolidity-merkle-trees)](https://www.npmjs.com/package/@polytope-labs/solidity-merkle-trees)

This library contains the implementations of various merkle tree verification algorithms. Currently supported algorithms:
<br />
 - [x] Merkle Trees (supports unbalanced trees).
 - [x] Merkle Mountain Ranges.
 - [ ] Merkle-Patricia Trie (Soon™).

## Installation

```
npm install @polytope-labs/solidity-merkle-trees
```

## Merkle Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.0;

import "@polytope-labs/solidity-merkle-trees/lib/MerkleMultiProof.sol";

contract YourContract {
    function verify(
        bytes32 root,
        Node[][] memory proof,
        Node[] leaves
    ) public {
        require(MerkleMultiProof.verifyProof(root, proof, leaves), "Invalid proof");
    }
}
```

You can generate the 2D merkle multi proofs using this rust lib [polytope-labs/rs-merkle](https://github.com/polytope-labs/rs-merkle)

## Merkle Mountain Range Multi Proofs

This algorithm is based on the research done here: https://research.polytope.technology/merkle-mountain-range-multi-proofs

You can use it to verify proofs like so:

```solidity
pragma solidity ^0.8.0;

import "@polytope-labs/solidity-merkle-trees/lib/MerkleMountainRange.sol";

contract YourContract {
    function verify(
        bytes32 root,
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) public {
        require(MerkleMountainRange.verifyProof(root, proof, leaves, mmrSize), "Invalid proof");
    }
}
```

You can derive the k-indices for the mmr leaves using this rust lib [polytope-labs/merkle-mountain-range](https://github.com/polytope-labs/merkle-mountain-range).

## License

This library is licensed under the [Apache 2.0 License](./LICENSE), Copyright (c) 2023 Polytope Labs.