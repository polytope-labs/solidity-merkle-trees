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

    function mid(NibbleSlice self, uint256 i) public pure returns (NibbleSlice) {
        return NibbleSlice(self, self.offset + i);
    }

    function isEmpty(NibbleSlice self) public pure returns (bool) {
        return NibbleSliceOps.len(self) == 0;
    }

    function eq(NibbleSlice self, NibbleSlice other) public pure returns (bool) {
        return NibbleSliceOps.len(self) == NibbleSliceOps.len(other) && NibbleSliceOps.startsWith(self, other);
    }

    function at(NibbleSlice self, uint256 i) public pure returns (uint256) {
        //todo: https://github.com/paritytech/trie/blob/0b5b7a54bda23c815c130310a513bdb38251ed12/trie-db/src/nibble/nibbleslice.rs#L109
        return 0;
    }

    function startsWith(NibbleSlice self, NibbleSlice other) public pure returns (bool) {
        // todo: https://github.com/paritytech/trie/blob/master/trie-db/src/nibble/nibbleslice.rs#L130
        return self;
    }
}

