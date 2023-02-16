pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

import "./Node.sol";
import "./HashDB.sol";

library NodeCodec {
    function isNibbledBranch(Node node) public view returns (bool) {
        return node.isNibbledBranch == true;
    }

    function isExtension(Node node) public view returns (bool) {
        return node.isExtension == true;
    }

    function isBranch(Node node) public view returns (bool) {
        return node.isBranch == true;
    }

    function isLeaf(Node node) public view returns (bool) {
        return node.isLeaf == true;
    }

    function isHash(NodeHandle node) public view returns (bool) {
        return node.isHash == true;
    }

    function isInline(NodeHandle node) public view returns (bool) {
        return node.isInline == true;
    }

    function asNibbledBranch(Node node) public view returns (NibbledBranch) {
        return node.nibbledBranch;
    }

    function asExtension(Node node) public view returns (Extension) {
        return node.extension;
    }

    function asBranch(Node node) public view returns (Branch) {
        return node.branch;
    }

    function asLeaf(Node node) public view returns (Leaf) {
        return node.leaf;
    }

    function asHash(NodeHandle node) public view returns (bytes32) {
        return node.hash;
    }

    function asInline(NodeHandle node) public view returns (bytes) {
        return node.inLine;
    }

    function loadValue(NodeHandle node, HashDB hashDB) public view returns (bytes) {
        if (node.isInline) {
            return node.inLine;
        } else if (node.isHash) {
            return hashDB.get(node.hash).opaqueBytes;
        }

        return bytes(0);
    }
}