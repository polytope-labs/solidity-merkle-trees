// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.17;

import "./MerkleMultiProof.sol";

/// @title A representation of a MerkleMountainRange leaf
struct MmrLeaf {
    // the leftmost index of a node
    uint256 k_index;
    // The position in the tree
    uint256 mmr_pos;
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
    /// @param mmrSize the size of the merkle tree
    /// @return bytes32 hash of the computed root node
    function CalculateRoot(
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) internal pure returns (bytes32) {
        uint256[] memory peaks = getPeaks(mmrSize);
        Iterator memory peakRoots = Iterator(0, new bytes32[](peaks.length));
        Iterator memory proofIter = Iterator(0, proof);

        for (uint256 p = 0; p < peaks.length; p++) {
            uint256 peak = peaks[p];
            MmrLeaf[] memory peakLeaves = new MmrLeaf[](0);
            if (leaves.length > 0) {
                (peakLeaves, leaves) = leavesForPeak(leaves, peak);
            }

            if (peakLeaves.length == 0) {
                if (proofIter.data.length == proofIter.offset) {
                    break;
                } else {
                    push(peakRoots, next(proofIter));
                }
            } else if (peakLeaves.length == 1 && peakLeaves[0].mmr_pos == peak) {
                push(peakRoots, peakLeaves[0].hash);
            } else {
                push(peakRoots, CalculatePeakRoot(peakLeaves, proofIter, peak));
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

    /// @notice calculate root hash of a sub peak of the merkle mountain
    /// @param peakLeaves  a list of nodes to provide proof for
    /// @param proofIter   a list of node hashes to traverse to compute the peak root hash
    /// @param peak    index of the peak node
    /// @return peakRoot a tuple containing the peak root hash, and the peak root position in the merkle
    function CalculatePeakRoot(
        MmrLeaf[] memory peakLeaves,
        Iterator memory proofIter,
        uint256 peak
    ) internal pure returns (bytes32)  {
        uint256[] memory current_layer;
        Node[] memory leaves;
        (leaves, current_layer) = mmrLeafToNode(peakLeaves);
        uint256 height = posToHeight(uint64(peak));
        Node[][] memory layers = new Node[][](height);

        for (uint256 i = 0; i < height; i++) {
            uint256[] memory siblings = siblingIndices(current_layer);
            uint256[] memory diff = difference(siblings, current_layer);
            if (diff.length == 0) {
                break;
            }

            layers[i] = new Node[](diff.length);
            for (uint256 j = 0; j < diff.length; j++) {
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
        uint256[] memory diff = new uint256[](left.length);
        uint256 d = 0;
        for (uint256 i = 0; i < left.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < right.length; j++) {
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

        uint256[] memory out = new uint256[](d);
        uint256 k = 0;
        while (k < d) {
            out[k] = diff[k];
            ++k;
        }

        return out;
    }

    /**
     * @dev calculates the index of each sibling index of the proof nodes
     * @dev proof nodes are the nodes that will be traversed to estimate the root hash
     * @param indices a list of proof nodes indices
     * @return uint256[] a list of sibling indices
     */
    function siblingIndices(uint256[] memory indices) internal pure returns (uint256[] memory) {
        uint256[] memory siblings = new uint256[](indices.length);

        for (uint256 i = 0; i < indices.length; i++) {
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
        uint256[] memory  parents = new uint256[](indices.length);

        for (uint256 i = 0; i < indices.length; i++) {
            parents[i] = indices[i] / 2;
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
        Node[] memory nodes = new Node[](leaves.length);
        uint256[] memory indices = new uint256[](leaves.length);
        while (i < leaves.length) {
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
     * @param peak the peak index of the root of the subtree
     * @return A tuple of 2 arrays of mountain merkle leaves. Index 1 and 2 represent left and right of the peak respectively
     */
    function leavesForPeak(
        MmrLeaf[] memory leaves,
        uint256 peak
    ) internal pure returns (MmrLeaf[] memory, MmrLeaf[] memory) {
        uint256 p = 0;
        for (;p < leaves.length; p++) {
            if (peak < leaves[p].mmr_pos) {
                break;
            }
        }

        uint256 len = p == 0 ? 0 : p;
        MmrLeaf[] memory left = new MmrLeaf[](len);
        MmrLeaf[] memory right = new MmrLeaf[](leaves.length - len);

        uint256 i = 0;
        while (i < left.length) {
            left[i] = leaves[i];
            ++i;
        }

        uint256 j = 0;
        while (i < leaves.length) {
            right[j] = leaves[i];
            ++i;
            ++j;
        }

        return (left, right);
    }

    /**
     * @notice Merkle mountain peaks computer
     * @notice Used internally to calculate a list of subtrees from the merkle mountain range
     * @param mmrSize the size of the merkle mountain range, or the height of the tree
     * @return uint265[] a list of the peak positions
     */
    function getPeaks(uint256 mmrSize) internal pure returns (uint256[] memory) {
        uint256 height;
        uint256 pos;
        (height, pos) = leftPeakHeightPos(mmrSize);
        uint256[] memory positions = new uint256[](height);
        uint256 p = 0;
        positions[p] = pos;
        p++;

        while (height > 0) {
            uint256 _height;
            uint256 _pos;
            (_height, _pos) = getRightPeak(height, pos, mmrSize);
            if (_height == 0 && _pos == 0) {
                break;
            }

            height = _height;
            pos = _pos;
            positions[p] = pos;
            ++p;
        }

        // copy array to new one, sigh solidity.
        uint256 i = 0;
        uint256[] memory out = new uint256[](p);
        while (i < p) {
            out[i] = positions[i];
            ++i;
        }

        return out;
    }

    function getRightPeak(uint256 height, uint256 pos, uint256 mmrSize) internal pure returns (uint256, uint256) {
        pos += siblingOffset(height);

        while (pos > (mmrSize - 1)) {
            if (height == 0) {
                return (0, 0);
            }
            --height;
            pos -= parentOffset(height);
        }

        return (height, pos);
    }

    function leftPeakHeightPos(uint256 mmrSize) internal pure returns (uint256, uint256) {
        uint256 height = 1;
        uint256 prevPos;
        uint256 pos = getPeakPosByHeight(height);
        while (pos < mmrSize) {
            ++height;
            prevPos = pos;
            pos = getPeakPosByHeight(height);
        }

        return (height - 1, prevPos);
    }

    function getPeakPosByHeight(uint256 height) internal pure returns (uint256) {
        return (1 << (height + 1)) - 2;
    }

    function posToHeight(uint64 pos) internal pure returns (uint64) {
        ++pos;

        while (!allOnes(pos)) {
            pos = jumpLeft(pos);
        }

        return (64 - countLeadingZeros(pos) - 1);
    }

    function siblingOffset(uint256 height) internal pure returns (uint256) {
        return (2 << height) - 1;
    }

    function parentOffset(uint256 height) internal pure returns (uint256) {
        return 2 << height;
    }

    function allOnes(uint64 pos) internal pure returns (bool) {
        return pos != 0 && countZeroes(pos) == countLeadingZeros(pos);
    }

    function jumpLeft(uint64 pos) internal pure returns (uint64) {
        uint64 len = 64 - countLeadingZeros(pos);
        uint64 msb = uint64(1 << (len - 1));
        return (pos - (msb - 1));
    }

    function countLeadingZeros(uint64 num) internal pure returns (uint64) {
        uint64 size = 64;
        uint64 count = 0;
        uint64  msb = uint64(1 << (size - 1));
        for (uint64 i = 0; i < size; i++) {
            if (((num << i) & msb) != 0) {
                break;
            }
            ++count;

        }

        return count;
    }

    function countZeroes(uint64 num) internal pure returns (uint256) {
        return 64 - countOnes(num);
    }

    function countOnes(uint64 num) internal pure returns (uint64) {
        uint64 count = 0;

        while (num !=  0) {
            num &= (num - 1);
            ++count;
        }

        return count;
    }

    function push(Iterator memory iterator, bytes32 data) internal pure {
        iterator.data[iterator.offset] = data;
        unchecked {
            ++iterator.offset;
        }
    }

    function next(Iterator memory iterator) internal pure returns (bytes32)  {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            ++iterator.offset;
        }

        return data;
    }

    function previous(Iterator memory iterator) internal pure returns (bytes32)  {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            --iterator.offset;
        }

        return data;
    }

    function leafIndexToPos(uint64 index) internal pure returns (uint64) {
        // mmr_size - H - 1, H is the height(intervals) of last peak
        return leafIndexToMmrSize(index) - trailingZeros(index + 1) - 1;
    }

    // count leading zeros: https://stackoverflow.com/a/45222481/6394734
    function trailingZeros(uint64 x) internal pure returns (uint64) {
        uint64 n = 0;

        if (x == 0) return(32);

        n = 1;
        if ((x & 0x0000FFFF) == 0) {n = n +16; x = x >>16;}
        if ((x & 0x000000FF) == 0) {n = n + 8; x = x >> 8;}
        if ((x & 0x0000000F) == 0) {n = n + 4; x = x >> 4;}
        if ((x & 0x00000003) == 0) {n = n + 2; x = x >> 2;}
        return n - (x & 1);
    }

    function leafIndexToMmrSize(uint64 index) internal pure returns (uint64) {
        // leaf index start with 0
        uint64 leaves_count = index + 1;

        // the peak count(k) is actually the count of 1 in leaves count's binary representation
        uint64 peak_count = countOnes(leaves_count);

        return 2 * leaves_count - peak_count;
    }
}