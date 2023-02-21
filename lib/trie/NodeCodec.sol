pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

import "./Node.sol";
import "./TrieDB.sol";

library NodeCodec {
    function isNibbledBranch(NodeKind memory node) external pure returns (bool) {
        return (node.isNibbledBranch || node.isNibbledHashedValueBranch || node.isNibbledValueBranch);
    }

    function isExtension(NodeKind memory node) external pure returns (bool) {
        return node.isExtension;
    }

    function isBranch(NodeKind memory node) external pure returns (bool) {
        return node.isBranch;
    }

    function isLeaf(NodeKind memory node) external pure returns (bool) {
        return (node.isLeaf || node.isHashedLeaf);
    }

    function isEmpty(NodeKind memory node) external pure returns (bool) {
        return node.isEmpty;
    }

    function isHash(NodeHandle memory node) external pure returns (bool) {
        return node.isHash;
    }

    function isInline(NodeHandle memory node) external pure returns (bool) {
        return node.isInline;
    }

    function loadValue(NodeHandle memory node, HashDB hashDB) external returns (bytes memory) {
        if (node.isInline) {
            return node.inLine.data;
        } else if (node.isHash) {
            return hashDB.get(node.hash);
        }

        return bytes("");
    }
}