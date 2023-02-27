pragma solidity ^0.8.17;

import "../Node.sol";
import "../Bytes.sol";
import { NibbleSliceOps } from "../NibbleSlice.sol";


// SPDX-License-Identifier: Apache2

library EthereumTrieDB {
    function decodeNodeKind(bytes memory encoded) external pure returns (NodeKind memory) {
        NodeKind memory node;
        ByteSlice memory input = ByteSlice(encoded, 0);
        // todo:

        return node;
    }

    function decodeLeaf(NodeKind memory node) external pure returns (Leaf memory) {
        Leaf memory leaf;
        ByteSlice memory input = node.data;

        // todo:

        return leaf;
    }

    function decodeExtension(NodeKind memory node) external pure returns (Extension memory) {
        Extension memory extension;
        ByteSlice memory input = node.data;

        // todo:

        return extension;
    }

    function decodeBranch(NodeKind memory node) external pure returns (Branch memory) {
        Branch memory branch;
        ByteSlice memory input = node.data;

        // todo:

        return branch;
    }
}