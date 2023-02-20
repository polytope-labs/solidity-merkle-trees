pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

import "./Node.sol";
import "./HashDB.sol";

library NodeCodec {
    function isNibbledBranch(Node memory node) external pure returns (bool) {
        return node.isNibbledBranch == true;
    }

    function isExtension(Node memory node) external pure returns (bool) {
        return node.isExtension == true;
    }

    function isBranch(Node memory node) external pure returns (bool) {
        return node.isBranch == true;
    }

    function isLeaf(Node memory node) external pure returns (bool) {
        return node.isLeaf == true;
    }

    function isEmpty(Node memory node) external pure returns (bool) {
        return node.isEmpty == true;
    }

    function isHash(NodeHandle memory node) external pure returns (bool) {
        return node.isHash == true;
    }

    function isInline(NodeHandle memory node) external pure returns (bool) {
        return node.isInline == true;
    }

    function loadValue(NodeHandle memory node, HashDB hashDB) external returns (bytes memory) {
        if (node.isInline) {
            return node.inLine.data;
        } else if (node.isHash) {
            return hashDB.get(node.hash).data;
        }

        return bytes("");
    }
}