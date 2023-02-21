pragma solidity ^0.8.17;

import "./Node.sol";

// SPDX-License-Identifier: Apache2

interface HashDB {
    function get(bytes32 hash) external returns (bytes memory);
    function length() external returns (uint256);

    function decode(bytes memory encoded) internal pure returns (NodeKind memory);
    function decodeNibbledBranch(NodeKind memory node) external pure returns (NibbledBranch memory);
    function decodeExtension(NodeKind memory node) external pure returns (Extension memory);
    function decodeBranch(NodeKind memory node) external pure returns (Branch memory);
    function decodeLeaf(NodeKind memory node) external pure returns (Leaf memory);
}