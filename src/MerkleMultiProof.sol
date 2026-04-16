// Copyright (C) Polytope Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
pragma solidity ^0.8.20;

/**
 * @title A Merkle Multi proof library
 * @author Polytope Labs
 * @dev Use this library to verify merkle tree leaves using merkle multi proofs.
 *      Supports both balanced and unbalanced trees.
 * @dev refer to research for more info. https://research.polytope.technology/merkle-multi-proofs
 */
library MerkleMultiProof {
    /*
     * @title A merkle tree leaf node
     *
     */
    struct Leaf {
        // 0-based index of the leaf
        uint256 index;
        // A hash of the leaf
        bytes32 hash;
    }

    // @dev Thrown when the proof array is exhausted before all siblings are resolved.
    error ProofExhausted();
    // @dev Thrown when leafCount is zero.
    error EmptyTree();
    // @dev Thrown when a leaf index is >= leafCount.
    error LeafIndexOutOfBounds();

    /**
     * @notice Verify a Merkle Multi Proof
     * @param root hash of the root node of the merkle tree
     * @param proof A list of proof node hashes needed to re-calculate root node.
     * @param leaves A list of the leaves with their indices to prove
     * @param leafCount Total number of leaves in the complete tree
     * @return boolean if the calculated root matches the provided root node
     */
    function VerifyProof(
        bytes32 root,
        bytes32[] memory proof,
        Leaf[] memory leaves,
        uint256 leafCount
    ) internal pure returns (bool) {
        return root == CalculateRoot(proof, leaves, leafCount);
    }

    /**
     * @notice Calculates the root hash of a merkle tree.
     * @dev Supports both balanced and unbalanced trees (leafCount need not be a
     *      power of 2). Converts leaf indices to 1-based tree positions, then
     *      walks up level by level pairing siblings. Missing siblings are consumed
     *      sequentially from the proof array. On the rightmost edge of an unbalanced
     *      tree, nodes whose sibling does not exist are promoted unchanged.
     *
     *      Position numbering (root = 1, children of i are 2i and 2i+1):
     *
     *               1  ← root
     *             /   \
     *            2     3
     *           / \   / \
     *          4   5 6   7        leaves at positions (1 << height) + index
     *
     *      Unbalanced example (5 leaves, height = 3):
     *
     *                1
     *              /   \
     *             2     3
     *            / \   / \
     *           4   5 6   7
     *          /\ /\ |
     *         8 9 .. 12         positions 13-15 don't exist, nodes promoted
     *
     *      At each level, siblings are identified via pos ^ 1.
     *      Even positions are left children, odd are right.
     *
     * @param proof Array of proof node hashes consumed as siblings during traversal
     * @param leaves Array of leaf nodes with their 0-based indices (must be sorted)
     * @param leafCount Total number of leaves in the complete tree
     * @return bytes32 The calculated root hash
     */
    function CalculateRoot(
        bytes32[] memory proof,
        Leaf[] memory leaves,
        uint256 leafCount
    ) internal pure returns (bytes32) {
        if (leafCount == 0) revert EmptyTree();

        uint256 len = leaves.length;
        uint256[] memory positions = new uint256[](len);
        bytes32[] memory hashes = new bytes32[](len);

        // Convert leaf indices to 1-based tree positions
        uint256 firstLeafPos = 1 << _ceilLog2(leafCount);
        for (uint256 i; i < len;) {
            if (leaves[i].index >= leafCount) revert LeafIndexOutOfBounds();
            hashes[i] = leaves[i].hash;
            unchecked {
                positions[i] = firstLeafPos + leaves[i].index;
                ++i;
            }
        }

        return _walk(positions, hashes, proof, leafCount);
    }

    /**
     * @dev Walk up the tree level by level, pairing siblings and hashing.
     *
     *      Supports unbalanced trees by tracking the number of valid nodes per
     *      level (`nodesAtLevel`). Starting from `leafCount`, this halves (with
     *      ceiling) each level. A sibling position that falls outside the valid
     *      range means it doesn't exist — the node is promoted unchanged.
     *
     */
    function _walk(
        uint256[] memory positions,
        bytes32[] memory hashes,
        bytes32[] memory proof,
        uint256 nodesAtLevel
    ) private pure returns (bytes32) {
        uint256 p;
        uint256 len = positions.length;

        while (positions[0] != 1) {
            uint256 lastValid = (1 << _log2(positions[0])) + nodesAtLevel - 1;
            uint256 j;

            for (uint256 i; i < len;) {
                uint256 pos = positions[i];
                bool hasSiblingInSet = i + 1 < len && positions[i + 1] == (pos ^ 1);
                bool siblingExists = (pos ^ 1) <= lastValid;

                bytes32 parent;
                if (hasSiblingInSet) {
                    parent = _hashPair(pos, hashes[i], hashes[i + 1]);
                    unchecked { i += 2; }
                } else if (siblingExists) {
                    parent = _hashPair(pos, hashes[i], proof[p]);
                    unchecked { ++p; ++i; }
                } else {
                    parent = hashes[i]; // unbalanced edge — promote
                    unchecked { ++i; }
                }

                hashes[j] = parent;
                positions[j] = pos >> 1;
                unchecked { ++j; }
            }

            len = j;
            nodesAtLevel = (nodesAtLevel + 1) >> 1;
        }

        return hashes[0];
    }

    /*
     * @dev Hash a node with its sibling, ordering by position (even = left child, odd = right child)
     * @param pos The 1-based tree position of the current node
     * @param current Hash of the current node
     * @param sibling Hash of the sibling node
     */
    function _hashPair(uint256 pos, bytes32 current, bytes32 sibling) private pure returns (bytes32 h) {
        if ((pos & 1) == 0) {
            assembly {
                mstore(0x0, current)
                mstore(0x20, sibling)
                h := keccak256(0x0, 0x40)
            }
        } else {
            assembly {
                mstore(0x0, sibling)
                mstore(0x20, current)
                h := keccak256(0x0, 0x40)
            }
        }
    }

    // @dev Compute ceil(log2(x))
    function _ceilLog2(uint256 x) private pure returns (uint256) {
        if (x <= 1) return 0;
        return _log2(x - 1) + 1;
    }

    // @dev Efficient floor(log2(x)) using bit-shifting
    function _log2(uint256 x) private pure returns (uint256 r) {
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            r := or(r, shl(2, lt(0xf, shr(r, x))))
            r := or(r, shl(1, lt(0x3, shr(r, x))))
            r := or(r, lt(0x1, shr(r, x)))
        }
    }
}
