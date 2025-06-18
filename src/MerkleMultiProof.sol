// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "./Types.sol";

/**
 * @title A Merkle Multi proof library
 * @author Polytope Labs
 * @dev Use this library to verify merkle tree leaves using merkle multi proofs
 * @dev refer to research for more info. https://research.polytope.technology/merkle-multi-proofs
 */
library MerkleMultiProof {
    /**
     * @notice Verify a Merkle Multi Proof
     * @param root hash of the root node of the merkle tree
     * @param proof A list of the merkle nodes along with their k-indices that are needed to re-calculate root node.
     * @param leaves A list of the leaves along with their k-indices to prove
     * @return boolean if the calculated root matches the provides root node
     */
    function VerifyProof(
        bytes32 root,
        Node[][] memory proof,
        Node[] memory leaves
    ) internal pure returns (bool) {
        return root == CalculateRoot(proof, leaves);
    }

    /**
     * @notice Verify a Merkle Multi Proof whose internal nodes are sorted
     * @param root hash of the root node of the merkle tree
     * @param proof A list of the merkle nodes along with their k-indices that are needed to re-calculate root node.
     * @param leaves A list of the leaves along with their k-indices to prove
     * @return boolean if the calculated root matches the provides root node
     */
    function VerifyProofSorted(
        bytes32 root,
        Node[][] memory proof,
        Node[] memory leaves
    ) internal pure returns (bool) {
        return root == CalculateRootSorted(proof, leaves);
    }

    /**
     * @notice Calculates the root hash of a balanced merkle tree.
     * Because the tree is balanced, we can devise a more efficient algorithm to calculate the root hash.
     *
     * @param proof Array of proof nodes containing position and hash
     * @param leaves Array of leaf nodes with their positions
     * @param numLeaves Total number of leaves in the complete tree
     * @return bytes32 The calculated root hash
     */
    function CalculateBalancedRoot(
        Node[] calldata proof,
        Node[] calldata leaves,
        uint256 numLeaves
    ) public pure returns (bytes32) {
        // Calculate tree height
        uint256 height = TreeHeight(numLeaves);

        // Initialize tracking variables
        uint256 p; // proof index
        uint256 f; // flattened index
        uint256 l; // leaf index

        // Create flattened array to store intermediate nodes
        Node[] memory flattened = new Node[](leaves.length);

        // Process leaves first
        while (l < leaves.length) {
            if (leaves[l].k_index % 2 == 0) {
                // Even position - need right sibling
                if (
                    p < proof.length &&
                    proof[p].k_index == leaves[l].k_index + 1
                ) {
                    // Sibling is in proof
                    flattened[f] = Node({
                        node: keccak256(
                            abi.encodePacked(leaves[l].node, proof[p].node)
                        ),
                        k_index: leaves[l].k_index / 2
                    });
                    f++;
                    p++;
                } else if (
                    l + 1 < leaves.length &&
                    leaves[l + 1].k_index == leaves[l].k_index + 1
                ) {
                    // Sibling is next leaf
                    flattened[f] = Node({
                        node: keccak256(
                            abi.encodePacked(leaves[l].node, leaves[l + 1].node)
                        ),
                        k_index: leaves[l].k_index / 2
                    });
                    f++;
                    l++;
                } else {
                    revert("Leaf missing right sibling");
                }
            } else {
                // Odd position - need left sibling
                if (
                    p < proof.length &&
                    proof[p].k_index == leaves[l].k_index - 1
                ) {
                    // Sibling is in proof
                    flattened[f] = Node({
                        node: keccak256(
                            abi.encodePacked(proof[p].node, leaves[l].node)
                        ),
                        k_index: proof[p].k_index / 2
                    });
                    f++;
                    p++;
                } else if (
                    l + 1 < leaves.length &&
                    leaves[l + 1].k_index == leaves[l].k_index - 1
                ) {
                    // Sibling is next leaf
                    flattened[f] = Node({
                        node: keccak256(
                            abi.encodePacked(leaves[l + 1].node, leaves[l].node)
                        ),
                        k_index: leaves[l + 1].k_index / 2
                    });
                    f++;
                    l++;
                } else {
                    revert("Leaf missing left sibling");
                }
            }
            l++;
        }

        // Move up the tree level
        height--;

        while (flattened[0].k_index != 1) {
            uint256 r; // read index
            uint256 w; // write index

            while (r < flattened.length) {
                if (
                    flattened[r].k_index == 0 ||
                    flattened[r].k_index >= 2 ** (height + 1)
                ) {
                    // End of current layer
                    if (height != 0) {
                        height--;
                    }
                    r = 0;
                    w = 0;
                    break;
                }

                if (flattened[r].k_index % 2 == 0) {
                    // Even position - need right sibling
                    if (
                        p < proof.length &&
                        proof[p].k_index == flattened[r].k_index + 1
                    ) {
                        // Sibling in proof
                        flattened[w] = Node({
                            node: keccak256(
                                abi.encodePacked(
                                    flattened[r].node,
                                    proof[p].node
                                )
                            ),
                            k_index: flattened[r].k_index / 2
                        });
                        w++;
                        p++;
                    } else if (
                        r + 1 < flattened.length &&
                        flattened[r + 1].k_index == flattened[r].k_index + 1
                    ) {
                        // Sibling in flattened
                        flattened[w] = Node({
                            node: keccak256(
                                abi.encodePacked(
                                    flattened[r].node,
                                    flattened[r + 1].node
                                )
                            ),
                            k_index: flattened[r].k_index / 2
                        });
                        w++;
                        r++;
                    } else {
                        revert("Node missing right sibling");
                    }
                } else {
                    // Odd position - need left sibling
                    if (
                        p < proof.length &&
                        proof[p].k_index == flattened[r].k_index - 1
                    ) {
                        // Sibling in proof
                        flattened[w] = Node({
                            node: keccak256(
                                abi.encodePacked(
                                    proof[p].node,
                                    flattened[r].node
                                )
                            ),
                            k_index: proof[p].k_index / 2
                        });
                        w++;
                        p++;
                    } else if (
                        r + 1 < flattened.length &&
                        flattened[r + 1].k_index == flattened[r].k_index - 1
                    ) {
                        // Sibling in flattened
                        flattened[w] = Node({
                            node: keccak256(
                                abi.encodePacked(
                                    flattened[r + 1].node,
                                    flattened[r].node
                                )
                            ),
                            k_index: flattened[r + 1].k_index / 2
                        });
                        w++;
                        r++;
                    } else {
                        revert("Node missing left sibling");
                    }
                }
                r++;
            }
        }

        return flattened[0].node;
    }

    /// @notice Calculate the hash of the root node
    /// @dev Use this function to calculate the hash of the root node
    /// @param proof A list of the merkle nodes along with their k-indices that are needed to re-calculate root node.
    /// @param leaves A list of the leaves along with their k-indices to prove
    /// @return Hash of root node, value is a bytes32 type
    function CalculateRoot(
        Node[][] memory proof,
        Node[] memory leaves
    ) internal pure returns (bytes32) {
        // holds the output from hashing a previous layer
        Node[] memory next_layer = new Node[](0);

        // merge leaves
        proof[0] = mergeSort(leaves, proof[0]);

        uint256 proof_length = proof.length;
        for (uint256 height = 0; height < proof_length; height++) {
            Node[] memory current_layer = new Node[](0);

            if (next_layer.length == 0) {
                current_layer = proof[height];
            } else {
                current_layer = mergeSort(proof[height], next_layer);
            }

            next_layer = new Node[](div_ceil(current_layer.length, 2));

            uint256 p = 0;
            uint256 current_layer_length = current_layer.length;
            for (uint256 index = 0; index < current_layer_length; index += 2) {
                if (index + 1 >= current_layer_length) {
                    Node memory node = current_layer[index];
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    next_layer[p] = node;
                } else {
                    Node memory node;
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    node.node = _optimizedHash(
                        current_layer[index].node,
                        current_layer[index + 1].node
                    );
                    next_layer[p] = node;
                    unchecked {
                        p++;
                    }
                }
            }
        }

        // we should have arrived at the root node
        require(next_layer.length == 1);

        return next_layer[0].node;
    }

    /// @notice Calculate the hash of the root node using a sorted node approach.
    /// @dev Use this function to calculate the hash of the root node
    /// @param proof A list of the merkle nodes that are needed to re-calculate root node.
    /// @param leaves A list of the leaves to prove
    /// @return Hash of root node, value is a bytes32 type
    function CalculateRootSorted(
        Node[][] memory proof,
        Node[] memory leaves
    ) internal pure returns (bytes32) {
        // holds the output from hashing a previous layer
        Node[] memory next_layer = new Node[](0);

        // merge leaves
        proof[0] = mergeSort(leaves, proof[0]);

        uint256 proof_length = proof.length;
        for (uint256 height = 0; height < proof_length; height++) {
            Node[] memory current_layer = new Node[](0);

            if (next_layer.length == 0) {
                current_layer = proof[height];
            } else {
                current_layer = mergeSort(proof[height], next_layer);
            }
            uint256 current_layer_length = current_layer.length;
            uint256 p = 0;

            next_layer = new Node[](div_ceil(current_layer_length, 2));
            for (uint256 index = 0; index < current_layer_length; index += 2) {
                if (index + 1 >= current_layer_length) {
                    Node memory node = current_layer[index];
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    next_layer[p] = node;
                } else {
                    Node memory node;
                    bytes32 a = current_layer[index].node;
                    bytes32 b = current_layer[index + 1].node;
                    if (a < b) {
                        node.node = _optimizedHash(a, b);
                    } else {
                        node.node = _optimizedHash(b, a);
                    }
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    next_layer[p] = node;
                    unchecked {
                        p++;
                    }
                }
            }
        }

        // we should have arrived at the root node
        require(next_layer.length == 1);

        return next_layer[0].node;
    }

    function div_floor(uint256 x, uint256 y) internal pure returns (uint256) {
        return x / y;
    }

    function div_ceil(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 result = x / y;
        if (x % y != 0) {
            unchecked {
                result += 1;
            }
        }

        return result;
    }

    /// @notice an internal function to merge two arrays and sort them at the same time.
    /// @dev compares the k-index of each node and sort in increasing order
    /// @param arr1 leftmost index in arr
    /// @param arr2 highest index in arr
    function mergeSort(
        Node[] memory arr1,
        Node[] memory arr2
    ) internal pure returns (Node[] memory) {
        // merge the two arrays
        uint256 i = 0;
        uint256 j = 0;
        uint256 k = 0;
        uint256 arr1_length = arr1.length;
        uint256 arr2_length = arr2.length;
        uint256 out_len = arr1_length + arr2_length;
        Node[] memory out = new Node[](out_len);

        while (i < arr1_length && j < arr2_length) {
            if (arr1[i].k_index < arr2[j].k_index) {
                out[k] = arr1[i];
                unchecked {
                    i++;
                    k++;
                }
            } else {
                out[k] = arr2[j];
                unchecked {
                    j++;
                    k++;
                }
            }
        }

        while (i < arr1_length) {
            out[k] = arr1[i];
            unchecked {
                i++;
                k++;
            }
        }

        while (j < arr2_length) {
            out[k] = arr2[j];
            unchecked {
                j++;
                k++;
            }
        }

        return out;
    }

    /// @notice compute the keccak256 hash of two nodes
    /// @param node1 hash of one of the two nodes
    /// @param node2 hash of the other of the two nodes
    function _optimizedHash(
        bytes32 node1,
        bytes32 node2
    ) internal pure returns (bytes32 hash) {
        assembly {
            // use EVM scratch space, its memory safe
            mstore(0x0, node1)
            mstore(0x20, node2)
            hash := keccak256(0x0, 0x40)
        }
    }

    /// @notice compute the height of the tree whose total number of leaves is given, it accounts for unbalanced trees.
    /// @param leavesCount number of leaves in the tree
    /// @return height of the tree
    function TreeHeight(uint256 leavesCount) internal pure returns (uint256) {
        uint256 height = Math.log2(leavesCount, Math.Rounding.Up);
        if (!isPowerOfTwo(leavesCount)) {
            unchecked {
                height++;
            }
        }

        return height;
    }

    function isPowerOfTwo(uint256 x) internal pure returns (bool) {
        if (x == 0) {
            return false;
        }

        return (x & (x - 1)) == 0;
    }
}
