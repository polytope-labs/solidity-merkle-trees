pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2
struct Node {
    uint32 index;
    bytes32 node;
}

library MerkleMultiProof {
    function verifyMultiProof(bytes32 root, Node[][] calldata proof)
        public
        pure
        returns (bool)
    {
        return root == calculateMultiRoot(proof);
    }

    function calculateMultiRoot(Node[][] calldata proof)
        public
        pure
        returns (bytes32)
    {
        // holds the output from hashing a previous layer
        Node[] memory previous_layer;

        for (uint256 layer = 0; layer < proof.length; layer++) {
            Node[] memory layer_nodes;
            if (previous_layer[0].node == bytes32(0)) {
                layer_nodes = proof[layer];
            } else {
                layer_nodes = merge_proofs(proof[layer], previous_layer);
                quick_sort(layer_nodes, 0, layer_nodes.length - 1);
                delete previous_layer;
            }

            uint32 i = 0;
            for (uint256 index = 0; index < layer_nodes.length; index += 2) {
                if (index + 1 >= layer_nodes.length) {
                    previous_layer[i] = layer_nodes[index];
                    previous_layer[i].index = div_floor(
                        layer_nodes[index].index,
                        2
                    );
                } else {
                    Node memory node;
                    node.index = div_floor(layer_nodes[index].index, 2);
                    node.node = keccak256(
                        abi.encodePacked(
                            layer_nodes[index].node,
                            layer_nodes[index + 1].node
                        )
                    );
                    previous_layer[i] = node;
                }
                i++;
            }
        }

        require(previous_layer.length == 2);

        return
            keccak256(
                abi.encodePacked(previous_layer[0].node, previous_layer[1].node)
            );
    }

    function div_floor(uint32 x, uint32 y) public pure returns (uint32) {
        uint32 result = x / y;
        if (x % y != 0) {
            result - 1;
        }

        return result;
    }

    function quick_sort(
        Node[] memory arr,
        uint256 left,
        uint256 right
    ) public pure {
        uint256 i = left;
        uint256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].index;
        while (i <= j) {
            while (arr[uint256(i)].index < pivot) i++;
            while (pivot < arr[uint256(j)].index) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                    arr[uint256(j)],
                    arr[uint256(i)]
                );
                i++;
                j--;
            }
        }
        if (left < j) quick_sort(arr, left, j);
        if (i < right) quick_sort(arr, i, right);
    }

    function merge_proofs(Node[] memory proof1, Node[] memory proof2)
        public
        pure
        returns (Node[] memory)
    {
        Node[] memory returnArr = new Node[](proof1.length + proof2.length);

        uint256 i = 0;
        for (; i < proof1.length; i++) {
            returnArr[i] = proof1[i];
        }

        uint256 j = 0;
        while (j < proof1.length) {
            returnArr[i++] = proof2[j++];
        }

        return returnArr;
    }
}