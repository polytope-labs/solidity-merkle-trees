pragma solidity ^0.8.17;

import "./HashDB.sol";

// SPDX-License-Identifier: Apache2

contract ParachainHashDB is HashDB {
    mapping(bytes32 => bytes) internal db;

    constructor(bytes[] proof) {
        for (uint256 i = 0; i < proof.length; i++) {
            db[keccak256(proof[i])] = proof[i];
        }
    }
}