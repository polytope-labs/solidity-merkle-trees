// SPDX-License-Identifier: Apache2
pragma solidity ^0.8.17;

import "./Node.sol";


library TrieDB {
    function get(TrieNode[] memory nodes, bytes32 hash) public pure returns (bytes memory) {
        for (uint256 i = 0; i < nodes.length; i++) {
            if (nodes[i].hash == hash) {
                return nodes[i].node;
            }
        }
        revert("Incomplete Proof!");
    }

    function load(TrieNode[] memory nodes, NodeHandle memory node) external pure returns (bytes memory) {
        if (node.isInline) {
            return node.inLine;
        } else if (node.isHash) {
            return get(nodes, node.hash);
        }

        return bytes("");
    }
}