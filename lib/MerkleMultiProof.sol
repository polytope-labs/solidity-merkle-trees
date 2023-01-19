pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2
struct Node {
    uint256 k_index;
    bytes32 node;
}

library MerkleMultiProof {
    function verifyProof(bytes32 root, Node[][] memory proof, Node[] memory leaves)
        public
        pure
        returns (bool)
    {
        return root == calculateRoot(proof, leaves);
    }

    function calculateRoot(Node[][] memory proof, Node[] memory leaves)
        public
        pure
        returns (bytes32)
    {
        // holds the output from hashing a previous layer
        Node[] memory next_layer = new Node[](0);

        // merge leaves
        Node[] memory base = new Node[](leaves.length + proof[0].length);
        mergeArrays(base, leaves, proof[0]);
        quickSort(base, 0, base.length - 1);
        proof[0] = base;

        for (uint256 height = 0; height < proof.length; height++) {
            Node[] memory current_layer = new Node[](0);

            if (next_layer.length == 0) {
                current_layer = proof[height];
            } else {
                current_layer = new Node[](
                    proof[height].length + next_layer.length
                );
                mergeArrays(current_layer, proof[height], next_layer);
                // todo: insertion sort isn't possible with solidity, sigh.
                quickSort(current_layer, 0, current_layer.length - 1);
                delete next_layer;
            }

            next_layer = new Node[](div_ceil(current_layer.length, 2));

            uint256 p = 0;
            for (uint256 index = 0; index < current_layer.length; index += 2) {
                if (index + 1 >= current_layer.length) {
                    Node memory node = current_layer[index];
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    next_layer[p] = node;
                } else {
                    Node memory node;
                    node.k_index = div_floor(current_layer[index].k_index, 2);
                    node.node = keccak256(
                        abi.encodePacked(
                            current_layer[index].node,
                            current_layer[index + 1].node
                        )
                    );
                    next_layer[p] = node;
                    p++;
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
            result += 1;
        }

        return result;
    }

    function quickSort(
        Node[] memory arr,
        uint256 left,
        uint256 right
    ) internal pure {
        uint256 i = left;
        uint256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].k_index;
        while (i <= j) {
            while (arr[uint256(i)].k_index < pivot) i++;
            while (pivot < arr[uint256(j)].k_index) if (j > 0) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                    arr[uint256(j)],
                    arr[uint256(i)]
                );
                i++;
                if (j > 0) j--;
            }
        }
        if (left < j) quickSort(arr, left, j);
        if (i < right) quickSort(arr, i, right);
    }

    function mergeArrays(
        Node[] memory out,
        Node[] memory arr1,
        Node[] memory arr2
    ) internal pure {
        // merge the two arrays
        uint256 i = 0;
        while (i < arr1.length) {
            out[i] = arr1[i];
            i++;
        }

        uint256 j = 0;
        while (j < arr2.length) {
            out[i] = arr2[j];
            i++;
            j++;
        }
    }
}
