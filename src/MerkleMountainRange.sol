// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.17;

import "./MerkleMultiProof.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "forge-std/Test.sol";

/// @title A representation of a MerkleMountainRange leaf
struct MmrLeaf {
    // the leftmost index of a node
    uint256 k_index;
    // The position in the tree
    uint256 leaf_index;
    // The hash of the position in the tree
    bytes32 hash;
}

struct Iterator {
    uint256 offset;
    bytes32[] data;
}

/**
 * @title A Merkle Mountain Range proof library
 * @author Polytope Labs
 * @notice Use this library to verify the leaves of a merkle mountain range tree
 * @dev refer to research for more info. https://research.polytope.technology/merkle-mountain-range-multi-proofs
 */
library MerkleMountainRange {
    /// @notice Verify that merkle proof is accurate
    /// @notice This calls CalculateRoot(...) under the hood
    /// @param root hash of the Merkle's root node
    /// @param proof a list of nodes required for the proof to be verified
    /// @param leaves a list of mmr leaves to prove
    /// @return boolean if the calculated root matches the provides root node
    function VerifyProof(bytes32 root, bytes32[] memory proof, MmrLeaf[] memory leaves, uint256 mmrSize)
        internal
        pure
        returns (bool)
    {
        return root == CalculateRoot(proof, leaves, mmrSize);
    }

    /// @notice Calculate merkle root
    /// @notice this method allows computing the root hash of a merkle tree using Merkle Mountain Range
    /// @param proof A list of the merkle nodes that are needed to re-calculate root node.
    /// @param leaves a list of mmr leaves to prove
    /// @param leafCount the size of the merkle tree
    /// @return bytes32 hash of the computed root node
    function CalculateRoot(bytes32[] memory proof, MmrLeaf[] memory leaves, uint256 leafCount)
        internal
        pure
        returns (bytes32)
    {
        // special handle the only 1 leaf MMR
        if (leafCount == 1 && leaves.length == 1 && leaves[0].leaf_index == 0) {
            return leaves[0].hash;
        }

        uint256[] memory subtrees = subtreeHeights(leafCount);
        uint256 length = subtrees.length;
        Iterator memory peakRoots = Iterator(0, new bytes32[](length));
        Iterator memory proofIter = Iterator(0, proof);

        uint256 current_subtree = 0;
        for (uint256 p = 0; p < length; p++) {
            uint256 height = subtrees[p];
            current_subtree += 2 ** height;

            MmrLeaf[] memory subtreeLeaves = new MmrLeaf[](0);
            if (leaves.length > 0) {
                (subtreeLeaves, leaves) = leavesForSubtree(leaves, current_subtree);
            }

            if (subtreeLeaves.length == 0) {
                if (proofIter.data.length == proofIter.offset) {
                    break;
                } else {
                    push(peakRoots, next(proofIter));
                }
            } else if (subtreeLeaves.length == 1 && height == 0) {
                push(peakRoots, subtreeLeaves[0].hash);
            } else {
                push(peakRoots, CalculateSubtreeRoot(subtreeLeaves, proofIter, height));
            }
        }

        unchecked {
            peakRoots.offset--;
        }

        while (peakRoots.offset != 0) {
            bytes32 right = previous(peakRoots);
            bytes32 left = previous(peakRoots);
            unchecked {
                ++peakRoots.offset;
            }
            peakRoots.data[peakRoots.offset] = keccak256(abi.encodePacked(right, left));
        }

        return peakRoots.data[0];
    }

    function subtreeHeights(uint256 leavesLength) internal pure returns (uint256[] memory) {
        uint256 maxSubtrees = 64;
        uint256[] memory indices = new uint256[](maxSubtrees);
        uint256 i = 0;
        uint256 current = leavesLength;
        for (; i < maxSubtrees; i++) {
            if (current == 0) {
                break;
            }
            uint256 log = Math.log2(current);
            indices[i] = log;
            current = current - 2 ** log;
        }

        // resize array?, sigh solidity.
        uint256 excess = maxSubtrees - i;
        assembly {
            mstore(indices, sub(mload(indices), excess))
        }

        return indices;
    }

    /// @notice calculate root hash of a subtree of the merkle mountain
    /// @param peakLeaves  a list of nodes to provide proof for
    /// @param proofIter   a list of node hashes to traverse to compute the peak root hash
    /// @param height    Height of the subtree
    /// @return peakRoot a tuple containing the peak root hash, and the peak root position in the merkle
    function CalculateSubtreeRoot(MmrLeaf[] memory peakLeaves, Iterator memory proofIter, uint256 height)
        internal
        pure
        returns (bytes32)
    {
        uint256[] memory current_layer;
        Node[] memory leaves;
        (leaves, current_layer) = mmrLeafToNode(peakLeaves);

        Node[][] memory layers = new Node[][](height);
        for (uint256 i = 0; i < height; i++) {
            uint256 nodelength = 2 ** (height - i);
            if (current_layer.length == nodelength) {
                break;
            }

            uint256[] memory siblings = siblingIndices(current_layer);
            uint256[] memory diff = difference(siblings, current_layer);

            uint256 length = diff.length;
            layers[i] = new Node[](length);
            for (uint256 j = 0; j < length; j++) {
                layers[i][j] = Node(diff[j], next(proofIter));
            }

            current_layer = parentIndices(siblings);
        }

        return MerkleMultiProof.CalculateRoot(layers, leaves);
    }

    /**
     * @notice difference ensures all nodes have a sibling.
     * @dev left and right are designed to be equal length array
     * @param left a list of hashes
     * @param right a list of hashes to compare
     * @return uint256[] a new array with difference
     */
    function difference(uint256[] memory left, uint256[] memory right) internal pure returns (uint256[] memory) {
        uint256 length = left.length;
        uint256 rightLength = right.length;

        uint256[] memory diff = new uint256[](length);
        uint256 d = 0;
        for (uint256 i = 0; i < length; i++) {
            bool found = false;
            for (uint256 j = 0; j < rightLength; j++) {
                if (left[i] == right[j]) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                diff[d] = left[i];
                d++;
            }
        }

        // resize array?, sigh solidity.
        uint256 excess = length - d;
        assembly {
            mstore(diff, sub(mload(diff), excess))
        }

        return diff;
    }

    /**
     * @dev calculates the index of each sibling index of the proof nodes
     * @dev proof nodes are the nodes that will be traversed to estimate the root hash
     * @param indices a list of proof nodes indices
     * @return uint256[] a list of sibling indices
     */
    function siblingIndices(uint256[] memory indices) internal pure returns (uint256[] memory) {
        uint256 length = indices.length;
        uint256[] memory siblings = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            uint256 index = indices[i];
            if (index == 0) {
                siblings[i] = index + 1;
            } else if (index % 2 == 0) {
                siblings[i] = index + 1;
            } else {
                siblings[i] = index - 1;
            }
        }

        return siblings;
    }

    /**
     * @notice Compute Parent Indices
     * @dev Used internally to calculate the indices of the parent nodes of the provided proof nodes
     * @param indices a list of indices of proof nodes in a merkle mountain
     * @return uint256[] a list of parent indices for each index provided
     */
    function parentIndices(uint256[] memory indices) internal pure returns (uint256[] memory) {
        uint256 length = indices.length;
        uint256[] memory parents = new uint256[](length);
        uint256 k = 0;

        for (uint256 i = 0; i < length; i++) {
            uint256 index = indices[i] / 2;
            if (k > 0 && parents[k - 1] == index) {
                continue;
            }
            parents[k] = index;
            unchecked {
                ++k;
            }
        }

        // resize array?, sigh solidity.
        uint256 excess = length - k;

        assembly {
            mstore(parents, sub(mload(parents), excess))
        }

        return parents;
    }

    /**
     * @notice Convert Merkle mountain Leaf to a Merkle Node
     * @param leaves list of merkle mountain range leaf
     * @return A tuple with the list of merkle nodes and the list of nodes at 0 and 1 respectively
     */
    function mmrLeafToNode(MmrLeaf[] memory leaves) internal pure returns (Node[] memory, uint256[] memory) {
        uint256 i = 0;
        uint256 length = leaves.length;
        Node[] memory nodes = new Node[](length);
        uint256[] memory indices = new uint256[](length);
        while (i < length) {
            nodes[i] = Node(leaves[i].k_index, leaves[i].hash);
            indices[i] = leaves[i].k_index;
            ++i;
        }

        return (nodes, indices);
    }

    /**
     * @notice Get a meountain peak's leaves
     * @notice this splits the leaves into either side of the peak [left & right]
     * @param leaves a list of mountain merkle leaves, for a subtree
     * @param leafIndex the index of the leaf of the next subtree
     * @return A tuple of 2 arrays of mountain merkle leaves. Index 1 and 2 represent left and right of the peak respectively
     */
    function leavesForSubtree(MmrLeaf[] memory leaves, uint256 leafIndex)
        internal
        pure
        returns (MmrLeaf[] memory, MmrLeaf[] memory)
    {
        uint256 p = 0;
        uint256 length = leaves.length;
        for (; p < length; p++) {
            if (leafIndex <= leaves[p].leaf_index) {
                break;
            }
        }

        uint256 len = p == 0 ? 0 : p;
        MmrLeaf[] memory left = new MmrLeaf[](len);
        MmrLeaf[] memory right = new MmrLeaf[](length - len);

        uint256 i = 0;
        uint256 leftLength = left.length;
        while (i < leftLength) {
            left[i] = leaves[i];
            ++i;
        }

        uint256 j = 0;
        while (i < length) {
            right[j] = leaves[i];
            ++i;
            ++j;
        }

        return (left, right);
    }

    function push(Iterator memory iterator, bytes32 data) internal pure {
        iterator.data[iterator.offset] = data;
        unchecked {
            ++iterator.offset;
        }
    }

    function next(Iterator memory iterator) internal pure returns (bytes32) {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            ++iterator.offset;
        }

        return data;
    }

    function previous(Iterator memory iterator) internal pure returns (bytes32) {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            --iterator.offset;
        }

        return data;
    }
}
