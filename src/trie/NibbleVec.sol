pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

struct NibbleVec {
    bytes data;
}

library NibbleVecOps {
    function fromHex(
        bytes memory hexBytes
    ) internal pure returns (NibbleVec memory) {
        return NibbleVec(hexBytes);
    }

    function isLeaf(NibbleVec memory self) internal pure returns (bool) {
        return self.data[self.data.length - 1] == bytes1(uint8(16));
    }

    function fromRaw(
        bytes memory rawBytes,
        uint8 is_leaf
    ) internal pure returns (NibbleVec memory) {
        require(is_leaf == 0 || is_leaf == 1, "is_leaf value not accepted");
        uint size = rawBytes.length * 2 + is_leaf;
        bytes memory hexBytes = new bytes(size);
        uint j = 0;
        for (uint256 i = 0; i < rawBytes.length; i++) {
            hexBytes[j] = bytes1(uint8(rawBytes[i]) / 16);
            hexBytes[j + 1] = bytes1(uint8(rawBytes[i]) % 16);
            j = j + 2;
        }
        if (is_leaf == 1) {
            hexBytes[j] = bytes1(uint8(16));
        }
        return NibbleVec(hexBytes);
    }

    function fromCompact(
        bytes memory compactBytes
    ) internal pure returns (NibbleVec memory) {
        uint8 flag = uint8(compactBytes[0]);
        require(flag & 192 == 0, "reserved flag bits used");
        uint8 prefix = flag >> 4;
        //uint8 is_odd = prefix & 1 == 1 ? 1 : 0;
        uint8 is_leaf = prefix & 2 == 2 ? 1 : 0;
        uint size = (compactBytes.length - 1) * 2 + is_leaf /*+ is_odd*/;
        bytes memory hexBytes = new bytes(size);
        uint j = 0;
        // if (is_odd == 1) {
        //     hexBytes[j] = bytes1(flag % 16);
        //     j = j + 1;
        // }
        for (uint256 i = 1; i < compactBytes.length; i++) {
            hexBytes[j] = bytes1(uint8(compactBytes[i]) / 16);
            hexBytes[j + 1] = bytes1(uint8(compactBytes[i]) % 16);
            j = j + 2;
        }
        if (is_leaf == 1) {
            hexBytes[j] = bytes1(uint8(16));
        }
        return NibbleVec(hexBytes);
    }

    function encodeRaw(
        NibbleVec memory self
    ) internal pure returns (bytes memory, bool) {
        uint size = self.data.length / 2;
        bytes memory bytesArr = new bytes(size);
        uint j = 0;
        for (uint256 i = 0; i < size * 2; i = i + 2) {
            bytesArr[j] = bytes1(
                uint8(self.data[i]) * 16 + uint8(self.data[i + 1])
            );

            j++;
        }
        return (bytesArr, isLeaf(self));
    }
}
