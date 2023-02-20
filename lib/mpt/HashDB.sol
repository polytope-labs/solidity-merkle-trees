pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

interface HashDB {
    function get(bytes32 hash) external returns (Node memory);
    function length() external returns (uint256);
    
    function decodeNibbledBranch(Node memory node) external pure returns (NibbledBranch memory);
    function decodeExtension(Node memory node) external pure returns (Extension memory);
    function decodeBranch(Node memory node) external pure returns (Branch memory);
    function decodeLeaf(Node memory node) external pure returns (Leaf memory);
}