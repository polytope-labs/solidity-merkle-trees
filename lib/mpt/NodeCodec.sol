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
        return leaf;
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