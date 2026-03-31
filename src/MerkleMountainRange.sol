/* Copyright (C) Polytope Labs Ltd. */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.17;

/**
 * @title A Merkle Mountain Range proof library
 * @author Polytope Labs
 * @notice Use this library to verify the merkle multi proofs of a merkle mountain range tree
 * @dev refer to research for more info. https://research.polytope.technology/merkle-mountain-range-multi-proofs
 */
library MerkleMountainRange {
    /* @dev Thrown when the proof array is exhausted before all siblings are resolved. */
    error ProofExhausted();
    /* @dev Thrown when leafCount is zero. */
    error EmptyTree();

    /*
     * @title A merkle mountain range leaf node
     *
     * An MMR with 14 leaves decomposes into subtrees of size 8, 4, 2:
     *
     *    Subtree 1          Subtree 2       Subtree 3
     *       /\                 /\               /\
     *      /  \               /  \             /  \
     *     /    \             /    \           L12  L13
     *    /\ .. /\           /\   /\
     *   L0 L1 .. L6 L7    L8 L9 L10 L11
     *
     *   index: 0-based leaf position across the entire MMR
     */
    struct Leaf {
        /* 0-based index of the leaf across the entire MMR */
        uint256 index;
        /* A hash of the leaf */
        bytes32 hash;
    }
    
    /* @dev Iterator for tracking a contiguous range of leaves in an array */
    struct LeafIterator {
        /* Start index of the range */
        uint256 offset; 
        /* Length of the range */
        uint256 length; 
        /* Reference to the underlying leaves array */
        Leaf[] data; 
    }

    /*
     * @dev A bidirectional iterator over a bytes32 array, used for sequential
     *      consumption of proof elements and accumulation of peak roots.
     */
    struct HashIterator {
        /* Current position in the array */
        uint256 offset;
        /* Reference to the underlying data */
        bytes32[] data;
    }

    /*
     * @notice Verify that merkle proof is accurate
     * @notice This calls CalculateRoot(...) under the hood
     * @param root hash of the merkle mountain range tree
     * @param proof a list of nodes required for the proof to be verified
     * @param leaves a list of mmr leaves to prove
     * @param leafCount the total leaf count of the merkle mountain range
     * @return boolean if the calculated root matches the provided root node
     */
    function VerifyProof(bytes32 root, bytes32[] memory proof, Leaf[] memory leaves, uint256 leafCount)
        internal
        pure
        returns (bool)
    {
        return root == CalculateRoot(proof, leaves, leafCount);
    }

    /*
     * @notice Calculate merkle mountain range root
     * @dev Decomposes leafCount into subtrees, computes each subtree root,
     *      then bags the peaks right-to-left:
     *
     *      leafCount = 14 = 8 + 4 + 2  →  3 subtrees
     *
     *        S1 (8 leaves)    S2 (4 leaves)    S3 (2 leaves)
     *           /\                /\               /\
     *          /  \              /  \             L12 L13
     *         /\  /\            /\  /\
     *        .. .. .. ..      L8 L9 L10 L11
     *
     *      ROOT = hash( hash(S3, S2), S1 )
     *
     * @param proof A list of the merkle nodes that are needed to re-calculate root node.
     * @param leaves a list of mmr leaves to prove
     * @param leafCount the total leaf count of the merkle mountain range
     * @return bytes32 hash of the computed root node
     */
    function CalculateRoot(bytes32[] memory proof, Leaf[] memory leaves, uint256 leafCount)
        internal
        pure
        returns (bytes32)
    {
        if (leafCount == 0) revert EmptyTree();

        /* special handle the only 1 leaf MMR */
        if (leafCount == 1 && leaves.length == 1 && leaves[0].index == 0) {
            return leaves[0].hash;
        }

        HashIterator memory peakRoots = HashIterator(0, new bytes32[](_popcount(leafCount)));
        HashIterator memory proofIter = HashIterator(0, proof);
        LeafIterator memory leafIter = LeafIterator(0, leaves.length, leaves);

        uint256 nextSubtreeStart;
        uint256 remaining = leafCount;
        while (remaining != 0) {
            uint256 height = _log2(remaining);
            uint256 subtreeSize = 1 << height;
            remaining -= subtreeSize;
            nextSubtreeStart += subtreeSize;

            LeafIterator memory subtreeLeaves = _subtreeLeaves(leafIter, nextSubtreeStart);

            if (subtreeLeaves.length == 0) {
                if (proofIter.data.length == proofIter.offset) {
                    break;
                } else {
                    _push(peakRoots, _next(proofIter));
                }
            } else if (subtreeLeaves.length == 1 && height == 0) {
                _push(peakRoots, subtreeLeaves.data[subtreeLeaves.offset].hash);
            } else {
                uint256 subtreeStartPos;
                unchecked { subtreeStartPos = 2 * subtreeSize - nextSubtreeStart; }
                _push(peakRoots, _subtreeRoot(subtreeLeaves, proofIter, subtreeStartPos));
            }
        }

        unchecked {
            peakRoots.offset--;
        }

        while (peakRoots.offset != 0) {
            bytes32 right = _previous(peakRoots);
            bytes32 left = _previous(peakRoots);
            unchecked {
                ++peakRoots.offset;
            }
            bytes32 hash;
            assembly {
                mstore(0x0, right)
                mstore(0x20, left)
                hash := keccak256(0x0, 0x40)
            }
            peakRoots.data[peakRoots.offset] = hash;
        }

        return peakRoots.data[0];
    }

    /*
     * @notice Get a subtree's leaves
     * @dev Partitions the leaf iterator so that leaves belonging to the current subtree
     *      are returned, and the iterator is advanced past them.
     * @param leafIter Iterator tracking the current leaf range
     * @param nextSubtreeStart The first leaf index belonging to the next subtree
     * @return LeafIterator for the current subtree's leaves
     */
    function _subtreeLeaves(LeafIterator memory leafIter, uint256 nextSubtreeStart)
        internal
        pure
        returns (LeafIterator memory)
    {
        uint256 end = leafIter.offset + leafIter.length;
        uint256 newOffset = leafIter.offset;

        for (; newOffset < end;) {
            if (nextSubtreeStart <= leafIter.data[newOffset].index) {
                break;
            }
            unchecked {
                ++newOffset;
            }
        }

        uint256 newLength = newOffset - leafIter.offset;
        LeafIterator memory subtreeIter = LeafIterator(leafIter.offset, newLength, leafIter.data);
        leafIter.offset = newOffset;
        leafIter.length -= newLength;

        return subtreeIter;
    }

    /*
     * @notice Calculate root hash of a subtree of the merkle mountain
     * @dev Converts leaf indices to tree positions, then walks up pairing siblings:
     *
     *      Subtree 2 (subtreeSize=4, leaves 8-11):
     *
     *              1  ← peak root
     *            /   \
     *           2     3          position = subtreeStartPos + leafIndex
     *          / \   / \
     *         4   5 6   7        e.g. leaf 10 → pos 6
     *         │   │ │   │
     *        L8  L9 L10 L11
     *
     *      At each level, siblings are paired (pos ^ 1) and hashed.
     *      Missing siblings are consumed from the proof.
     *
     * @param leafIter An iterator representing the range of leaves for the subtree
     * @param proofIter Iterator over proof node hashes consumed as siblings during traversal
     * @param subtreeStartPos Precomputed constant such that position = subtreeStartPos + leafIndex (may underflow, corrected on addition)
     * @return bytes32 The computed peak root hash
     */
    function _subtreeRoot(LeafIterator memory leafIter, HashIterator memory proofIter, uint256 subtreeStartPos)
        internal
        pure
        returns (bytes32)
    {
        uint256 length = leafIter.length;
        uint256 offset = leafIter.offset;

        uint256[] memory positions = new uint256[](length);
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length;) {
            hashes[i] = leafIter.data[offset + i].hash;
            unchecked {
                positions[i] = subtreeStartPos + leafIter.data[offset + i].index;
                ++i;
            }
        }
        uint256 len = length;

        /* Walk up the tree, hashing with proof nodes — reuse arrays in-place */
        while (positions[0] != 1) {
            uint256 nIdx;
            uint256 i;

            while (i < len) {
                uint256 pos = positions[i];

                if (i + 1 < len && positions[i + 1] == (pos ^ 1)) {
                    /* Both siblings known */
                    hashes[nIdx] = _hashPair(pos, hashes[i], hashes[i + 1]);
                    positions[nIdx] = pos >> 1;
                    unchecked {
                        ++nIdx;
                    }
                    i += 2;
                } else {
                    /* Sibling is a proof node */
                    if (proofIter.offset >= proofIter.data.length) revert ProofExhausted();
                    hashes[nIdx] = _hashPair(pos, hashes[i], _next(proofIter));
                    positions[nIdx] = pos >> 1;
                    unchecked {
                        ++nIdx;
                        ++i;
                    }
                }
            }

            /* Shrink arrays to the number of parent nodes written */
            len = nIdx;
            assembly {
                mstore(positions, nIdx)
                mstore(hashes, nIdx)
            }
        }

        return hashes[0];
    }

    /* @dev Push a value onto the iterator and advance the offset */
    function _push(HashIterator memory iterator, bytes32 data) internal pure {
        iterator.data[iterator.offset] = data;
        unchecked {
            ++iterator.offset;
        }
    }

    /* @dev Read the current value and advance the iterator forward */
    function _next(HashIterator memory iterator) internal pure returns (bytes32) {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            ++iterator.offset;
        }

        return data;
    }

    /* @dev Read the current value and move the iterator backward */
    function _previous(HashIterator memory iterator) internal pure returns (bytes32) {
        bytes32 data = iterator.data[iterator.offset];
        unchecked {
            --iterator.offset;
        }

        return data;
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

    /* @dev Count the number of set bits (population count). Used to determine the number of peaks in the MMR. */
    function _popcount(uint256 x) private pure returns (uint256 count) {
        while (x != 0) {
            x &= x - 1;
            unchecked {
                ++count;
            }
        }
    }

    /* @dev Efficient floor(log2(x)) using bit-shifting */
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
