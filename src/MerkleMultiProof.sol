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

import {Node} from "./Types.sol";

/**
 * @title A Merkle Multi proof library
 * @author Polytope Labs
 * @dev Use this library to verify merkle tree leaves using merkle multi proofs
 * @dev refer to research for more info. https://research.polytope.technology/merkle-multi-proofs
 */
library MerkleMultiProof {
    error LeafMissingSibling();
    error NodeMissingSibling();

    /**
     * @notice Verify a Merkle Multi Proof
     * @param root hash of the root node of the merkle tree
     * @param proof A list of the merkle nodes along with their node indices that are needed to re-calculate root node.
     * @param leaves A list of the leaves along with their node indices to prove
     * @param leavesCount Total number of leaves in the complete tree
     * @return boolean if the calculated root matches the provided root node
     */
    function VerifyProof(
        bytes32 root,
        Node[] memory proof,
        Node[] memory leaves,
        uint256 leavesCount
    ) internal pure returns (bool) {
        return root == CalculateRoot(proof, leaves, leavesCount);
    }

    /**
     * @notice Calculates the root hash of a merkle tree.
     * @dev By assigning nodes a 1-based positional index within their tree level, we can
     * efficiently walk up the tree pairing siblings. Even indices are left children,
     * odd indices are right children. Parent index = child index >> 1. Also works for
     * unbalanced trees by promoting unpaired nodes.
     * @param proof Array of proof nodes containing position and hash
     * @param leaves Array of leaf nodes with their positions
     * @param leavesCount Total number of leaves in the complete tree
     * @return bytes32 The calculated root hash
     */
    function CalculateRoot(
        Node[] memory proof,
        Node[] memory leaves,
        uint256 leavesCount
    ) internal pure returns (bytes32) {
        uint256 height = _ceilLog2(leavesCount);

        uint256 p;
        uint256 f;
        uint256 l;

        uint256 leavesLen = leaves.length;
        uint256 proofLen = proof.length;

        Node[] memory flattened = new Node[](leavesLen);

        while (l < leavesLen) {
            if ((leaves[l].nodeIndex & 1) == 0) {
                if (
                    p < proofLen &&
                    proof[p].nodeIndex == leaves[l].nodeIndex + 1
                ) {
                    flattened[f].node = _optimizedHash(leaves[l].node, proof[p].node);
                    flattened[f].nodeIndex = leaves[l].nodeIndex >> 1;
                    unchecked {
                        ++f;
                        ++p;
                    }
                } else if (
                    l + 1 < leavesLen &&
                    leaves[l + 1].nodeIndex == leaves[l].nodeIndex + 1
                ) {
                    flattened[f].node = _optimizedHash(leaves[l].node, leaves[l + 1].node);
                    flattened[f].nodeIndex = leaves[l].nodeIndex >> 1;
                    unchecked {
                        ++f;
                        ++l;
                    }
                } else {
                    flattened[f].node = leaves[l].node;
                    flattened[f].nodeIndex = leaves[l].nodeIndex >> 1;
                    unchecked {
                        ++f;
                        ++l;
                    }
                }
            } else {
                if (
                    p < proofLen &&
                    proof[p].nodeIndex == leaves[l].nodeIndex - 1
                ) {
                    flattened[f].node = _optimizedHash(proof[p].node, leaves[l].node);
                    flattened[f].nodeIndex = proof[p].nodeIndex >> 1;
                    unchecked {
                        ++f;
                        ++p;
                    }
                } else if (
                    l + 1 < leavesLen &&
                    leaves[l + 1].nodeIndex == leaves[l].nodeIndex - 1
                ) {
                    flattened[f].node = _optimizedHash(leaves[l + 1].node, leaves[l].node);
                    flattened[f].nodeIndex = leaves[l + 1].nodeIndex >> 1;
                    unchecked {
                        ++f;
                        ++l;
                    }
                } else {
                    revert LeafMissingSibling();
                }
            }
            l++;
        }

        // Trim flattened to actual size before processing upper levels
        assembly {
            mstore(flattened, f)
        }
        uint256 flatLen = f;

        unchecked {
            --height;
        }

        while (flattened[0].nodeIndex != 1) {
            uint256 r;
            uint256 w;

            while (r < flatLen) {
                if (
                    flattened[r].nodeIndex == 0 ||
                    flattened[r].nodeIndex >= 1 << (height + 1)
                ) {
                    if (height != 0) {
                        height--;
                    }
                    r = 0;
                    w = 0;
                    break;
                }

                if ((flattened[r].nodeIndex & 1) == 0) {
                    if (
                        p < proofLen &&
                        proof[p].nodeIndex == flattened[r].nodeIndex + 1
                    ) {
                        flattened[w].node = _optimizedHash(flattened[r].node, proof[p].node);
                        flattened[w].nodeIndex = flattened[r].nodeIndex >> 1;
                        unchecked {
                            ++w;
                            ++p;
                        }
                    } else if (
                        r + 1 < flatLen &&
                        flattened[r + 1].nodeIndex == flattened[r].nodeIndex + 1
                    ) {
                        flattened[w].node = _optimizedHash(flattened[r].node, flattened[r + 1].node);
                        flattened[w].nodeIndex = flattened[r].nodeIndex >> 1;
                        unchecked {
                            ++w;
                            ++r;
                        }
                    } else {
                        flattened[w].node = flattened[r].node;
                        flattened[w].nodeIndex = flattened[r].nodeIndex >> 1;
                        unchecked {
                            ++w;
                            ++r;
                        }
                    }
                } else {
                    if (
                        p < proofLen &&
                        proof[p].nodeIndex == flattened[r].nodeIndex - 1
                    ) {
                        flattened[w].node = _optimizedHash(proof[p].node, flattened[r].node);
                        flattened[w].nodeIndex = proof[p].nodeIndex >> 1;
                        unchecked {
                            ++w;
                            ++p;
                        }
                    } else if (
                        r + 1 < flatLen &&
                        flattened[r + 1].nodeIndex == flattened[r].nodeIndex - 1
                    ) {
                        flattened[w].node = _optimizedHash(flattened[r + 1].node, flattened[r].node);
                        flattened[w].nodeIndex = flattened[r + 1].nodeIndex >> 1;
                        unchecked {
                            ++w;
                            ++r;
                        }
                    } else {
                        revert NodeMissingSibling();
                    }
                }

                unchecked {
                    ++r;
                }
            }

            // Trim flattened to the number of nodes written this level
            flatLen = w;
            assembly {
                mstore(flattened, w)
            }
        }

        return flattened[0].node;
    }

    /// @notice Compute the keccak256 hash of two nodes
    /// @param node1 hash of the first node
    /// @param node2 hash of the second node
    function _optimizedHash(
        bytes32 node1,
        bytes32 node2
    ) internal pure returns (bytes32 hash) {
        assembly {
            mstore(0x0, node1)
            mstore(0x20, node2)
            hash := keccak256(0x0, 0x40)
        }
    }

    /// @dev Compute ceil(log2(x))
    function _ceilLog2(uint256 x) private pure returns (uint256) {
        if (x <= 1) return 0;
        return _log2(x - 1) + 1;
    }

    /// @dev Efficient floor(log2(x)) using bit-shifting
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
