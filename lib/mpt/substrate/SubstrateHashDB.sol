pragma solidity ^0.8.17;

import "./HashDB.sol";
import "./Node.sol";
import { ScaleCodec } from "./ScaleCodec.sol";

// SPDX-License-Identifier: Apache2

contract SubstrateHashDB is HashDB {
    uint8 public constant EMPTY_TRIE = 0x45;
    
    mapping(bytes32 => Node) internal db;

    constructor(bytes[] memory proof) {
        for (uint256 i = 0; i < proof.length; i++) {
            db[keccak256(proof[i])] = decode(proof[i]);
        }
    }

    function decode(bytes memory encoded) internal pure returns (Node memory) {
        Node memory node;
        uint8 b = ScaleCodec.readByteAtIndex(encoded, 0);

        if (b == EMPTY_TRIE) {
            node.isEmpty = true;
        } else if (b == 0) {
        } else if (b == 1) {
            node.isLeaf = true;
        } else if (b == 2) {
            node.isExtension = true;
        } else if (b == 3) {
            node.isBranch = true;
        } else if (b == 4) {
            node.isNibbledBranch = true;
        } else {
            node.isOpaqueBytes = true;
        }
        node.data = encoded[1:];

        return node;
    }

    function get(bytes32 hash) public pure returns (Node memory) {
        return this.db[hash];
    }

    function decodeNibbledBranch(Node memory node) external pure returns (NibbledBranch memory) {
        NibbledBranch memory nibbledBranch;

        return nibbledBranch;
    }

    function decodeExtension(Node memory node) external pure returns (Extension memory) {
        Extension memory extension;
        return extension;
    }

    function decodeBranch(Node memory node) external pure returns (Branch memory) {
        Branch memory branch;
        return branch;
    }

    function decodeLeaf(Node memory node) external pure returns (Leaf memory) {
        Leaf memory leaf;
        // ok so the memory layout is: (Vec<u8>, )
        return leaf;
    }

    function length() public returns (uint256) {
        return this.db.length;
    }
}