pragma solidity 0.8.17;

import "../Node.sol";
import "../Bytes.sol";
import {NibbleSliceOps} from "../NibbleSlice.sol";
import "./RLPReader.sol";

// SPDX-License-Identifier: Apache2

library EthereumTrieDB {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;

    bytes constant HASHED_NULL_NODE = hex"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    function decodeNodeKind(bytes memory encoded) external pure returns (NodeKind memory) {
        NodeKind memory node;
        ByteSlice memory input = ByteSlice(encoded, 0);
        if (Bytes.equals(encoded, HASHED_NULL_NODE)) {
            node.isEmpty = true;
            return node;
        }
        RLPReader.RLPItem[] memory itemList = encoded.toRlpItem().toList();
        uint256 numItems = itemList.length;
        if (numItems == 0) {
            node.isEmpty = true;
            return node;
        } else if (numItems == 2) {
            //It may be a leaf or extension
            bytes memory key = itemList[0].toBytes();
            uint256 prefix;
            assembly {
                let first := shr(248, mload(add(key, 32)))
                prefix := shr(4, first)
            }
            if (prefix == 2 || prefix == 3) {
                node.isLeaf = true;
            } else {
                node.isExtension = true;
            }
        } else if (numItems == 17) {
            node.isBranch = true;
        } else {
            revert("Invalid data");
        }
        node.data = input;
        return node;
    }

    function decodeLeaf(NodeKind memory node) external pure returns (Leaf memory) {
        Leaf memory leaf;
        RLPReader.RLPItem[] memory decoded = node.data.data.toRlpItem().toList();
        bytes memory data = decoded[1].toBytes();
        //Remove the first byte, which is the prefix and not present in the user provided key
        leaf.key = NibbleSlice(Bytes.substr(decoded[0].toBytes(), 1), 0);
        leaf.value = NodeHandle(false, bytes32(0), true, data);

        return leaf;
    }

    function decodeExtension(NodeKind memory node) external pure returns (Extension memory) {
        Extension memory extension;
        RLPReader.RLPItem[] memory decoded = node.data.data.toRlpItem().toList();
        bytes memory data = decoded[1].toBytes();
        uint8 isOdd = uint8(decoded[0].toBytes()[0] >> 4) & 0x01;
        //Remove the first byte, which is the prefix and not present in the user provided key
        extension.key = NibbleSlice(Bytes.substr(decoded[0].toBytes(), (isOdd + 1) % 2), isOdd);
        extension.node = NodeHandle(true, Bytes.toBytes32(data), false, new bytes(0));
        return extension;
    }

    function decodeBranch(NodeKind memory node) external pure returns (Branch memory) {
        Branch memory branch;
        RLPReader.RLPItem[] memory decoded = node.data.data.toRlpItem().toList();

        NodeHandleOption[16] memory childrens;

        for (uint256 i = 0; i < 16; i++) {
            bytes memory dataAsBytes = decoded[i].toBytes();
            if (dataAsBytes.length != 32) {
                childrens[i] = NodeHandleOption(false, NodeHandle(false, bytes32(0), false, new bytes(0)));
            } else {
                bytes32 data = Bytes.toBytes32(dataAsBytes);
                childrens[i] = NodeHandleOption(true, NodeHandle(true, data, false, new bytes(0)));
            }
        }
        if (isEmpty(decoded[16].toBytes())) {
            branch.value = NodeHandleOption(false, NodeHandle(false, bytes32(0), false, new bytes(0)));
        } else {
            branch.value = NodeHandleOption(true, NodeHandle(false, bytes32(0), true, decoded[16].toBytes()));
        }
        branch.children = childrens;

        return branch;
    }

    function isEmpty(bytes memory item) internal pure returns (bool) {
        return item.length > 0 && (item[0] == 0xc0 || item[0] == 0x80);
    }
}
