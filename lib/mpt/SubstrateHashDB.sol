pragma solidity ^0.8.17;

import "./HashDB.sol";
import "./Node.sol";

// SPDX-License-Identifier: Apache2

contract SubstrateHashDB is HashDB {
    mapping(bytes32 => Node) internal db;
    uint256 internal len;

    constructor(bytes[] proof) {
        for (uint256 i = 0; i < proof.length; i++) {
            db[keccak256(proof[i])] = decode(proof[i]);
        }
        len = proof.length;
    }

    function decode(bytes encoded) internal pure returns (Node) {
        Node node;
        // todo: https://github.com/paritytech/substrate/blob/7732f88c117ceb41b57a51402abd64f888acd013/primitives/trie/src/node_codec.rs#L95

        return node;
    }

    function get(bytes32 hash) public pure returns (Node) {
        return this.db[hash];
    }

    function length() public returns (uint256) {
        return len;
    }
}