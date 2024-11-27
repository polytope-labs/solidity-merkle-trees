// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/math/Math.sol";

import "./Types.sol";
import "./MerkleMultiProof.sol";

/**
 * @title A Merkle Mountain Range proof library
 * @author Polytope Labs
 * @notice Use this library to verify the leaves of a merkle mountain range tree
 * @dev refer to research for more info. https://research.polytope.technology/merkle-mountain-range-multi-proofs
 */
library MerkleMountainRange {
    struct LeafIterator {
        uint256 offset; // Start index of the range
        uint256 length; // Length of the range
    }

    /// @notice Verify that merkle proof is accurate
    /// @notice This calls CalculateRoot(...) under the hood
    /// @param root hash of the Merkle's root node
    /// @param proof a list of nodes required for the proof to be verified
    /// @param leaves a list of mmr leaves to prove
    /// @return boolean if the calculated root matches the provided root node
    function VerifyProof(
        bytes32 root,
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) internal pure returns (bool) {
        return root == CalculateRoot(proof, leaves, mmrSize);
    }

    /// @notice Calculate merkle root
    /// @notice this method allows computing the root hash of a merkle tree using Merkle Mountain Range
    /// @param proof A list of the merkle nodes that are needed to re-calculate root node.
    /// @param leaves a list of mmr leaves to prove
    /// @param leafCount the size of the merkle tree
    /// @return bytes32 hash of the computed root node
    function CalculateRoot(
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 leafCount
    ) internal pure returns (bytes32) {
        // special handle the only 1 leaf MMR
        if (leafCount == 1 && leaves.length == 1 && leaves[0].leaf_index == 0) {
            return leaves[0].hash;
        }

        uint256[] memory subtrees = subtreeHeights(leafCount);
        uint256 length = subtrees.length;
        Iterator memory peakRoots = Iterator(0, new bytes32[](length));
        Iterator memory proofIter = Iterator(0, proof);

        uint256 current_subtree;
        LeafIterator memory leafIter = LeafIterator(0, leaves.length);

        for (uint256 p; p < length; ) {
            uint256 height = subtrees[p];
            current_subtree += 2 ** height;

            // Get iterators for the current subtree leaves
            LeafIterator memory subtreeLeaves = getSubtreeLeaves(
                leaves,
                leafIter,
                current_subtree
            );

            if (subtreeLeaves.length == 0) {
                if (proofIter.data.length == proofIter.offset) {
                    break;
                } else {
                    push(peakRoots, next(proofIter));
                }
            } else if (subtreeLeaves.length == 1 && height == 0) {
                push(peakRoots, leaves[subtreeLeaves.offset].hash);
            } else {
                push(
                    peakRoots,
                    CalculateSubtreeRoot(leaves, subtreeLeaves, proofIter, height)
                );
            }

            unchecked {
                ++p;
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
            peakRoots.data[peakRoots.offset] = keccak256(
                abi.encodePacked(right, left)
            );
        }

        return peakRoots.data[0];
    }

    /// @notice Get a mountain peak's leaves using iterators
    /// @param leaves A list of mountain merkle leaves for a subtree
    /// @param leafIter Iterator tracking the current leaf range
    /// @param current_subtree The index of the current subtree
    /// @return LeafIterator for the current subtree's leaves
    function getSubtreeLeaves(
        MmrLeaf[] memory leaves,
        LeafIterator memory leafIter,
        uint256 current_subtree
    ) internal pure returns (LeafIterator memory) {
        uint256 end = leafIter.offset + leafIter.length;
        uint256 newOffset = leafIter.offset;

        for (; newOffset < end; ) {
            if (current_subtree <= leaves[newOffset].leaf_index) {
                break;
            }
            unchecked {
                ++newOffset;
            }
        }

        uint256 newLength = newOffset - leafIter.offset;
        LeafIterator memory subtreeIter = LeafIterator(leafIter.offset, newLength);
        leafIter.offset = newOffset;
        leafIter.length -= newLength;

        return subtreeIter;
    }

    function subtreeHeights(
        uint256 leavesLength
    ) internal pure returns (uint256[] memory) {
        uint256 maxSubtrees = 64;
        uint256[] memory indices = new uint256[](maxSubtrees);
        uint256 i;
        uint256 current = leavesLength;
        for (; i < maxSubtrees; ) {
            if (current == 0) {
                break;
            }
            uint256 log = Math.log2(current);
            indices[i] = log;
            current = current - 2 ** log;

            unchecked {
                ++i;
            }
        }

        // resize array?, sigh solidity.
        uint256 excess = maxSubtrees - i;
        assembly {
            mstore(indices, sub(mload(indices), excess))
        }

        return indices;
    }

    /// @notice Calculate root hash of a subtree of the merkle mountain
    /// @param leaves A list of all MMR leaves
    /// @param leafIter An iterator representing the range of leaves for the subtree
    /// @param proofIter A list of node hashes to traverse to compute the peak root hash
    /// @param height Height of the subtree
    /// @return bytes32 The computed peak root hash
    function CalculateSubtreeRoot(
        MmrLeaf[] memory leaves,
        LeafIterator memory leafIter,
        Iterator memory proofIter,
        uint256 height
    ) internal pure returns (bytes32) {
        // Convert the leaves within the iterator range to nodes
        (Node[] memory nodes, uint256[] memory current_layer) = mmrLeafToNode(leaves, leafIter);

        // Initialize the layers for MerkleMultiProof
        Node[][] memory layers = new Node[][](height);

        for (uint256 i; i < height; ) {
            uint256 nodelength = 2 ** (height - i);

            // If the current layer matches the expected node length, stop
            if (current_layer.length == nodelength) {
                break;
            }

            // Calculate sibling indices and nodes without siblings
            uint256[] memory siblings = siblingIndices(current_layer);
            uint256[] memory diff = difference(siblings, current_layer);

            // Prepare the next layer of nodes using the diff
            uint256 length = diff.length;
            layers[i] = new Node[](length);
            for (uint256 j; j < length; ) {
                layers[i][j] = Node(diff[j], next(proofIter));

                unchecked {
                    ++j;
                }
            }

            // Update the current layer to parent indices
            current_layer = parentIndices(siblings);

            unchecked {
                ++i;
            }
        }

        // Use MerkleMultiProof to compute the root of the layers
        return MerkleMultiProof.CalculateRoot(layers, nodes);
    }

    /**
     * @notice difference ensures all nodes have a sibling.
     * @dev left and right are designed to be equal length array
     * @param left a list of hashes
     * @param right a list of hashes to compare
     * @return uint256[] a new array with difference
     */
    function difference(
        uint256[] memory left,
        uint256[] memory right
    ) internal pure returns (uint256[] memory) {
        uint256 length = left.length;
        uint256 rightLength = right.length;

        uint256[] memory diff = new uint256[](length);
        uint256 d;
        for (uint256 i; i < length; ) {
            bool found;
            for (uint256 j; j < rightLength; ) {
                if (left[i] == right[j]) {
                    found = true;
                    break;
                }

                unchecked {
                    ++j;
                }
            }

            if (!found) {
                diff[d] = left[i];
                d++;
            }

            unchecked {
                ++i;
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
    function siblingIndices(
        uint256[] memory indices
    ) internal pure returns (uint256[] memory) {
        uint256 length = indices.length;
        uint256[] memory siblings = new uint256[](length);

        for (uint256 i; i < length; ) {
            uint256 index = indices[i];
            if (index == 0) {
                siblings[i] = index + 1;
            } else if (index % 2 == 0) {
                siblings[i] = index + 1;
            } else {
                siblings[i] = index - 1;
            }

            unchecked {
                ++i;
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
    function parentIndices(
        uint256[] memory indices
    ) internal pure returns (uint256[] memory) {
        uint256 length = indices.length;
        uint256[] memory parents = new uint256[](length);
        uint256 k;

        for (uint256 i; i < length; i++) {
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

    /// @notice Convert a range of MMR leaves to Merkle nodes
    /// @param leaves A list of all MMR leaves
    /// @param leafIter An iterator representing the range of leaves to convert
    /// @return Node[] The list of converted nodes
    /// @return uint256[] The indices of the nodes
    function mmrLeafToNode(
        MmrLeaf[] memory leaves,
        LeafIterator memory leafIter
    ) internal pure returns (Node[] memory, uint256[] memory) {
        uint256 length = leafIter.length;
        uint256 offset = leafIter.offset;

        Node[] memory nodes = new Node[](length);
        uint256[] memory indices = new uint256[](length);

        for (uint256 i = 0; i < length; i++) {
            nodes[i] = Node(leaves[offset + i].k_index, leaves[offset + i].hash);
            indices[i] = leaves[offset + i].k_index;
        }

        return (nodes, indices);
    }

    /**
     * @notice Get a mountain peak's leaves using iterators
     * @notice This splits the leaves into either side of the peak [left & right] by setting offsets and lengths
     * @param leaves A list of mountain merkle leaves for a subtree
     * @param leafIndex The index of the leaf of the next subtree
     * @return A tuple of two iterators representing the left and right ranges of the peak leaves
     */
    function leavesForSubtree(
        MmrLeaf[] memory leaves,
        uint256 leafIndex
    ) internal pure returns (LeafIterator memory, LeafIterator memory) {
        uint256 p;
        uint256 length = leaves.length;

        // Find the position where leafIndex splits the leaves
        for (; p < length; p++) {
            if (leafIndex <= leaves[p].leaf_index) {
                break;
            }
        }

        // Create iterators instead of copying into arrays
        LeafIterator memory left = LeafIterator(0, p);
        LeafIterator memory right = LeafIterator(p, length - p);

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

    function previous(
        Iterator memory iterator
    ) internal pure returns (bytes32) {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            --iterator.offset;
        }

        return data;
    }
}
