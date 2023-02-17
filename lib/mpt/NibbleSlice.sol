pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

struct NibbleSlice {
    bytes data;
    uint256 offset;
}

library NibbleSliceOps {

    uint256 constant NIBBLE_PER_BYTE = 2;
    uint256 constant BITS_PER_NIBBLE = 4;

    function len(NibbleSlice memory nibble) public pure returns (uint256) {
        return nibble.data.length * NIBBLE_PER_BYTE - nibble.offset;
    }

    function mid(NibbleSlice memory self, uint256 i) public pure returns (NibbleSlice memory) {
        return NibbleSlice(self.data, self.offset + i);
    }

    function isEmpty(NibbleSlice memory self) public pure returns (bool) {
        return len(self) == 0;
    }

    function eq(NibbleSlice calldata self, NibbleSlice calldata other) public pure returns (bool) {
        return len(self) == len(other) && startsWith(self, other);
    }

    function at(NibbleSlice memory self, uint256 i) public pure returns (uint256) {
        uint256 ix = (self.offset + i) / NIBBLE_PER_BYTE;
        uint256 pad = (self.offset + i) % NIBBLE_PER_BYTE;
        uint8 data = uint8(self.data[ix]);
        return (pad == 1) ? data & 0x0F : data >> BITS_PER_NIBBLE;
    }

    function startsWith(NibbleSlice calldata self, NibbleSlice calldata other) public pure returns (bool) {
        return commonPrefix(self, other) == len(other);
    }

    function commonPrefix(NibbleSlice calldata self, NibbleSlice calldata other) public pure returns (uint256) {
        uint256 self_align = self.offset % NIBBLE_PER_BYTE;
        uint256 other_align = other.offset % NIBBLE_PER_BYTE;

        if(self_align == other_align) {
            uint256 self_start = self.offset / NIBBLE_PER_BYTE;
            uint256 other_start = other.offset / NIBBLE_PER_BYTE;
            uint256 first = 0;

            if(self_align != 0) {
                if((self.data[self_start] & 0x0F) != (other.data[other_start] & 0x0F)) {
                    return 0;
                }
                ++self_start;
                ++other_start;
                ++first;
            }
            return biggestDepth(self.data[self_start:], other.data[other_start:]) + first;
        }else {
            uint256 s = min(len(self), len(other));
            uint256 i = 0;
            while(i < s) {
                if(at(self,i) != at(other, i)) {
                    break;
                }
                ++i;
            }
            return i;
        }
    }

    function biggestDepth(bytes calldata a, bytes calldata b) public pure returns (uint256) {
        uint256 upperBound = min(a.length, b.length);
        uint256 i = 0;
        while(i < upperBound) {
            if(a[i] != b[i]) {
                return i * NIBBLE_PER_BYTE + leftCommon(a[i], b[i]);
            }
            ++i;
        }
        return i * NIBBLE_PER_BYTE;
    }

    function leftCommon(bytes1 a, bytes1 b) public pure returns (uint256) {
        if (a == b) {
            return 2;
        }else if(uint8(a) & 0xF0 == uint8(b) & 0xF0) {
            return 1;
        }else {
            return 0;
        }
    }

    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return (a < b) ? a : b;
    }
}
