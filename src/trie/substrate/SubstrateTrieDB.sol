pragma solidity ^0.8.17;

import "../Node.sol";
import "../Bytes.sol";
import {NibbleSliceOps} from "../NibbleSlice.sol";

import {ScaleCodec} from "./ScaleCodec.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// SPDX-License-Identifier: Apache2

library SubstrateTrieDB {
    uint8 public constant FIRST_PREFIX = 0x00 << 6;
    uint8 public constant PADDING_BITMASK = 0x0F;
    uint8 public constant EMPTY_TRIE = FIRST_PREFIX | (0x00 << 4);
    uint8 public constant LEAF_PREFIX_MASK = 0x01 << 6;
    uint8 public constant BRANCH_WITH_MASK = 0x03 << 6;
    uint8 public constant BRANCH_WITHOUT_MASK = 0x02 << 6;
    uint8 public constant ALT_HASHING_LEAF_PREFIX_MASK =
        FIRST_PREFIX | (0x01 << 5);
    uint8 public constant ALT_HASHING_BRANCH_WITH_MASK =
        FIRST_PREFIX | (0x01 << 4);
    uint8 public constant NIBBLE_PER_BYTE = 2;
    uint256 public constant NIBBLE_SIZE_BOUND = uint256(type(uint16).max);
    uint256 public constant BITMAP_LENGTH = 2;
    uint256 public constant HASH_lENGTH = 32;

    function decodeNodeKind(
        bytes memory encoded
    ) internal pure returns (NodeKind memory) {
        NodeKind memory node;
        ByteSlice memory input = ByteSlice(encoded, 0);
        uint8 i = Bytes.readByte(input);

        if (i == EMPTY_TRIE) {
            node.isEmpty = true;
            return node;
        }

        uint8 mask = i & (0x03 << 6);

        if (mask == LEAF_PREFIX_MASK) {
            node.nibbleSize = decodeSize(i, input, 2);
            node.isLeaf = true;
        } else if (mask == BRANCH_WITH_MASK) {
            node.nibbleSize = decodeSize(i, input, 2);
            node.isNibbledValueBranch = true;
        } else if (mask == BRANCH_WITHOUT_MASK) {
            node.nibbleSize = decodeSize(i, input, 2);
            node.isNibbledBranch = true;
        } else if (mask == EMPTY_TRIE) {
            if (i & (0x07 << 5) == ALT_HASHING_LEAF_PREFIX_MASK) {
                node.nibbleSize = decodeSize(i, input, 3);
                node.isHashedLeaf = true;
            } else if (i & (0x0F << 4) == ALT_HASHING_BRANCH_WITH_MASK) {
                node.nibbleSize = decodeSize(i, input, 4);
                node.isNibbledHashedValueBranch = true;
            } else {
                // do not allow any special encoding
                revert("Unallowed encoding");
            }
        }
        node.data = input;

        return node;
    }

    function decodeNibbledBranch(
        NodeKind memory node
    ) internal pure returns (NibbledBranch memory) {
        NibbledBranch memory nibbledBranch;
        ByteSlice memory input = node.data;

        bool padding = node.nibbleSize % NIBBLE_PER_BYTE != 0;
        if (padding && (padLeft(uint8(input.data[input.offset])) != 0)) {
            revert("Bad Format!");
        }
        uint256 nibbleLen = ((node.nibbleSize +
            (NibbleSliceOps.NIBBLE_PER_BYTE - 1)) /
            NibbleSliceOps.NIBBLE_PER_BYTE);
        nibbledBranch.key = NibbleSlice(
            Bytes.read(input, nibbleLen),
            node.nibbleSize % NIBBLE_PER_BYTE
        );

        bytes memory bitmapBytes = Bytes.read(input, BITMAP_LENGTH);
        uint16 bitmap = uint16(ScaleCodec.decodeUint256(bitmapBytes));

        NodeHandleOption memory valueHandle;
        if (node.isNibbledHashedValueBranch) {
            valueHandle.isSome = true;
            valueHandle.value.isHash = true;
            valueHandle.value.hash = Bytes.toBytes32(
                Bytes.read(input, HASH_lENGTH)
            );
        } else if (node.isNibbledValueBranch) {
            uint256 len = ScaleCodec.decodeUintCompact(input);
            valueHandle.isSome = true;
            valueHandle.value.isInline = true;
            valueHandle.value.inLine = Bytes.read(input, len);
        }
        nibbledBranch.value = valueHandle;

        for (uint256 i = 0; i < 16; i++) {
            NodeHandleOption memory childHandle;
            if (valueAt(bitmap, i)) {
                childHandle.isSome = true;
                uint256 len = ScaleCodec.decodeUintCompact(input);
                //                revert(string.concat("node index: ", Strings.toString(len)));
                if (len == HASH_lENGTH) {
                    childHandle.value.isHash = true;
                    childHandle.value.hash = Bytes.toBytes32(
                        Bytes.read(input, HASH_lENGTH)
                    );
                } else {
                    childHandle.value.isInline = true;
                    childHandle.value.inLine = Bytes.read(input, len);
                }
            }
            nibbledBranch.children[i] = childHandle;
        }

        return nibbledBranch;
    }

    function decodeLeaf(
        NodeKind memory node
    ) internal pure returns (Leaf memory) {
        Leaf memory leaf;
        ByteSlice memory input = node.data;

        bool padding = node.nibbleSize % NIBBLE_PER_BYTE != 0;
        if (padding && padLeft(uint8(input.data[input.offset])) != 0) {
            revert("Bad Format!");
        }
        uint256 nibbleLen = (node.nibbleSize +
            (NibbleSliceOps.NIBBLE_PER_BYTE - 1)) /
            NibbleSliceOps.NIBBLE_PER_BYTE;
        bytes memory nibbleBytes = Bytes.read(input, nibbleLen);
        leaf.key = NibbleSlice(nibbleBytes, node.nibbleSize % NIBBLE_PER_BYTE);

        NodeHandle memory handle;
        if (node.isHashedLeaf) {
            handle.isHash = true;
            handle.hash = Bytes.toBytes32(Bytes.read(input, HASH_lENGTH));
        } else {
            uint256 len = ScaleCodec.decodeUintCompact(input);
            handle.isInline = true;
            handle.inLine = Bytes.read(input, len);
        }
        leaf.value = handle;

        return leaf;
    }

    function decodeSize(
        uint8 first,
        ByteSlice memory encoded,
        uint8 prefixMask
    ) internal pure returns (uint256) {
        uint8 maxValue = uint8(255 >> prefixMask);
        uint256 result = uint256(first & maxValue);

        if (result < maxValue) {
            return result;
        }

        result -= 1;

        while (result <= NIBBLE_SIZE_BOUND) {
            uint256 n = uint256(Bytes.readByte(encoded));
            if (n < 255) {
                return result + n + 1;
            }
            result += 255;
        }

        return NIBBLE_SIZE_BOUND;
    }

    function padLeft(uint8 b) internal pure returns (uint8) {
        return b & ~PADDING_BITMASK;
    }

    function valueAt(uint16 bitmap, uint256 i) internal pure returns (bool) {
        return bitmap & (uint16(1) << uint16(i)) != 0;
    }
}
