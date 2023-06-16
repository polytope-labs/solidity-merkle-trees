pragma solidity ^0.8.17;

import "../Node.sol";
import "../Bytes.sol";
import {NibbleSliceOps} from "../NibbleSlice.sol";
import "./RLPReader.sol";

// SPDX-License-Identifier: Apache2

library EthereumTrieDB {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;

    function decodeNodeKind(
        bytes memory encoded
    ) external pure returns (NodeKind memory) {
        NodeKind memory node;
        ByteSlice memory input = ByteSlice(encoded, 0);
        RLPReader.Iterator memory decoded = RLPReader
            .toRlpItem(encoded)
            .iterator();
        uint numItems = decoded.item.numItems();
        if (numItems == 0) {
            node.isEmpty = true;
            return node;
        } else if (numItems == 2) {
            //It may be a leaf or extension
            bytes memory key = decoded.item.toBytes();
            uint256 prefix;
            assembly {
                let first := shr(248, mload(add(key, 32)))
                prefix := shr(4, first)
            }
            if (prefix == 2) {
                node.isLeaf = true;
            } else {
                node.isExtension = true;
            }
        } else if (numItems == 17) {
            node.isBranch = true;
        } else {
            bytes memory data = decoded.item.toBytes();
            if (data[0] < 0xc0 && data.length == 32) {
                node.isLeaf = true;
                node.isHashedLeaf = true;
            } else {
                revert("Invalid data");
            }
        }
        node.data = input;
        return node;
    }

    function decodeLeaf(
        NodeKind memory node
    ) external pure returns (Leaf memory) {
        Leaf memory leaf;
        ByteSlice memory input = node.data;
        RLPReader.Iterator memory decoded = RLPReader
            .toRlpItem(input.data)
            .iterator();
        bytes memory key = decoded.item.toBytes();

        // todo: check if any transformation in needed on the key

        if (!node.isHashedLeaf) {
            bytes memory data = decoded.next().toBytes();

            leaf.key = NibbleSlice(key, 0);
            leaf.value = NodeHandle(false, bytes32(0), true, data);
        } else {
            leaf.key = NibbleSlice(key, 0);
            leaf.value = NodeHandle(
                true,
                Bytes.toBytes32(key),
                false,
                new bytes(0)
            );
        }
        return leaf;
    }

    function decodeExtension(
        NodeKind memory node
    ) external pure returns (Extension memory) {
        Extension memory extension;
        ByteSlice memory input = node.data;
        RLPReader.Iterator memory decoded = RLPReader
            .toRlpItem(input.data)
            .iterator();
        bytes memory key = decoded.item.toBytes();

        // todo: check if any transformation in needed on the key

        bytes memory data = decoded.next().toBytes();

        extension.key = NibbleSlice(key, 0);
        extension.node = NodeHandle(false, bytes32(0), true, data);

        return extension;
    }

    function decodeBranch(
        NodeKind memory node
    ) external pure returns (Branch memory) {
        Branch memory branch;
        ByteSlice memory input = node.data;
        RLPReader.Iterator memory decoded = RLPReader
            .toRlpItem(input.data)
            .iterator();

        NodeHandleOption[16] memory childrens;

        RLPReader.RLPItem memory current = decoded.next();
        for (uint256 i = 0; i < childrens.length; i++) {
            childrens[i] = NodeHandleOption(
                true,
                NodeHandle(false, bytes32(0), true, current.toBytes())
            );
            current = decoded.next();
        }
        if (current.len == 0) {
            branch.value = NodeHandleOption(
                false,
                NodeHandle(false, bytes32(0), false, new bytes(0))
            );
        } else {
            branch.value = NodeHandleOption(
                true,
                NodeHandle(false, bytes32(0), true, current.toBytes())
            );
        }

        return branch;
    }
}
