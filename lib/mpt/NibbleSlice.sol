pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

struct NibbleSlice {
    bytes data;
    uint256 offset;
}

library NibbleSliceOps {
    function len(NibbleSlice memory nibble) public pure returns (uint256) {
        return nibble.data.length * 2 - nibble.offset;
    }

    function mid(NibbleSlice memory self, uint256 i) public pure returns (NibbleSlice memory) {
        return NibbleSlice(self.data, self.offset + i);
    }

    function isEmpty(NibbleSlice memory self) public pure returns (bool) {
        return len(self) == 0;
    }

    function eq(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return len(self) == len(other) && startsWith(self, other);
    }

    function at(NibbleSlice memory self, uint256 i) public pure returns (uint256) {
        //todo: https://github.com/paritytech/trie/blob/0b5b7a54bda23c815c130310a513bdb38251ed12/trie-db/src/nibble/nibbleslice.rs#L109
        return 0;
    }

    function startsWith(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        // todo: https://github.com/paritytech/trie/blob/master/trie-db/src/nibble/nibbleslice.rs#L130
        return false;
    }
}

