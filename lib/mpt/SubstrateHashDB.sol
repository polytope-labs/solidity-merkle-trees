pragma solidity ^0.8.17;

import "./HashDB.sol";
import "./Node.sol";

// SPDX-License-Identifier: Apache2

contract ParachainHashDB is HashDB {
    mapping(bytes32 => Node) internal db;

    constructor(bytes[] proof) {
        for (uint256 i = 0; i < proof.length; i++) {
            db[keccak256(proof[i])] = decode(proof[i]);
        }
    }

    function decode(bytes encoded) internal pure returns (Node) {
        Node node;
        // oof.

        return node;
    }

    function get(bytes32 hash) public pure returns (Node) {
        return this.db[hash];
    }
}