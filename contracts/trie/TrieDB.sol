pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

interface ITrieDB {
    function decodeNodeKind(bytes memory encoded) external pure returns (NodeKind memory);
    function decodeNibbledBranch(NodeKind memory node) external pure returns (NibbledBranch memory);
    function decodeExtension(NodeKind memory node) external pure returns (Extension memory);
    function decodeBranch(NodeKind memory node) external pure returns (Branch memory);
    function decodeLeaf(NodeKind memory node) external pure returns (Leaf memory);
}

abstract contract TrieDB is ITrieDB {
    struct TrieNode {
        bool exists;
        bytes node;
    }

    mapping(bytes32 => TrieNode) internal db;

    constructor(bytes[] memory proof) {
        for (uint256 i = 0; i < proof.length; i++) {
            db[keccak256(proof[i])] = TrieNode(true, proof[i]);
        }
    }

    function get(bytes32 hash) public view returns (bytes memory) {
        TrieNode memory node = db[hash];
        require(node.exists, "Incomplete Proof!");
        return node.node;
    }

    function load(NodeHandle memory node) external view returns (bytes memory) {
        if (node.isInline) {
            return node.inLine;
        } else if (node.isHash) {
            return get(node.hash);
        }

        return bytes("");
    }
}