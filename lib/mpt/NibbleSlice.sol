pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

struct NibbleSlice {
    bytes data;
    uint256 offset;
}

library NibbleSliceOps {
    function len(NibbleSlice nibble) public pure returns (uint256) {
        return nibble.data.length * 2 - nibble.offset;
    }
}

