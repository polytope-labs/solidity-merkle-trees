pragma solidity ^0.8.17;

import "./NodeCodec.sol";

// SPDX-License-Identifier: Apache2

interface HashDB {
    function get(bytes32 hash) public returns (Node memory);
}