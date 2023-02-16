pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

interface HashDB {
    function get(bytes32 hash) external returns (Node memory);
    function length() external returns (uint256);
}