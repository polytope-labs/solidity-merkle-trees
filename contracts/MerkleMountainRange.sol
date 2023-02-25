pragma solidity ^0.8.17;

import "./MerkleMultiProof.sol";

// SPDX-License-Identifier: Apache2

struct MmrLeaf {
    uint256 k_index;
    uint256 mmr_pos;
    bytes32 hash;
}

library MerkleMountainRange {
    function VerifyProof(
        bytes32 root,
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) public pure returns (bool) {
        return root == CalculateRoot(proof, leaves, mmrSize);
    }

    function CalculateRoot(
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) public pure returns (bytes32) {
        uint256[] memory peaks = getPeaks(mmrSize);
        bytes32[] memory peakRoots = new bytes32[](peaks.length);
        uint256 pc = 0;
        uint256 prc = 0;

        for (uint256 p = 0; p < peaks.length; p++) {
            uint256 peak = peaks[p];
            MmrLeaf[] memory peakLeaves = new MmrLeaf[](0);
            if (leaves.length > 0) {
                (peakLeaves, leaves) = leavesForPeak(leaves, peak);
            }

            if (peakLeaves.length == 0) {
                if (proof.length == pc) {
                    break;
                } else {
                    peakRoots[prc] = proof[pc];
                    prc++;
                    pc++;
                }
            } else if (peakLeaves.length == 1 && peakLeaves[0].mmr_pos == peak) {
                peakRoots[prc] = peakLeaves[0].hash;
                prc++;
            } else {
                (peakRoots[prc], pc) = CalculatePeakRoot(peakLeaves, proof, peak, pc);
                prc++;
            }
        }

        prc--;
        while (prc != 0) {
            bytes32 right = peakRoots[prc];
            prc--;
            bytes32 left = peakRoots[prc];
            peakRoots[prc] = keccak256(abi.encodePacked(right, left));
        }

        return peakRoots[0];
    }

    function CalculatePeakRoot(
        MmrLeaf[] memory peakLeaves,
        bytes32[] memory proof,
        uint256 peak,
        uint256 pc
    ) public pure returns (bytes32, uint256)  {
        uint256[] memory current_layer;
        Node[] memory leaves;
        (leaves, current_layer) = mmrLeafToNode(peakLeaves);
        uint256 height = posToHeight(uint64(peak));
        Node[][] memory layers = new Node[][](height);

        for (uint256 i = 0; i < height; i++) {
            uint256[] memory siblings = siblingIndices(current_layer);
            uint256[] memory diff = difference(siblings, current_layer);
            if (diff.length == 0) {
                break;
            }

            layers[i] = new Node[](diff.length);
            for (uint256 j = 0; j < diff.length; j++) {
                layers[i][j] = Node(diff[j], proof[pc]);
                pc++;
            }

            current_layer = parentIndices(siblings);
        }

        return (MerkleMultiProof.CalculateRoot(layers, leaves), pc);
    }

    function difference(uint256[] memory left, uint256[] memory right) public pure returns (uint256[] memory) {
        uint256[] memory diff = new uint256[](left.length);
        uint256 d = 0;
        for (uint256 i = 0; i < left.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < right.length; j++) {
                if (left[i] == right[j]) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                diff[d] = left[i];
                d++;
            }
        }

        uint256[] memory out = new uint256[](d);
        uint256 k = 0;
        while (k < d) {
            out[k] = diff[k];
            k++;
        }

        return out;
    }

    function siblingIndices(uint256[] memory indices) public pure returns (uint256[] memory) {
        uint256[] memory siblings = new uint256[](indices.length);

        for (uint256 i = 0; i < indices.length; i++) {
            uint256 index = indices[i];
            if (index == 0) {
                siblings[i] = index + 1;
            } else if (index % 2 == 0) {
                siblings[i] = index + 1;
            } else {
                siblings[i] = index - 1;
            }
        }

        return siblings;
    }

    function parentIndices(uint256[] memory indices) public pure returns (uint256[] memory) {
        uint256[] memory  parents = new uint256[](indices.length);

        for (uint256 i = 0; i < indices.length; i++) {
            parents[i] = indices[i] / 2;
        }

        return parents;
    }

    function mmrLeafToNode(MmrLeaf[] memory leaves) public pure returns (Node[] memory, uint256[] memory) {
        uint256 i = 0;
        Node[] memory nodes = new Node[](leaves.length);
        uint256[] memory indices = new uint256[](leaves.length);
        while (i < leaves.length) {
            nodes[i] = Node(leaves[i].k_index, leaves[i].hash);
            indices[i] = leaves[i].k_index;
            i++;
        }

        return (nodes, indices);
    }

    function leavesForPeak(
        MmrLeaf[] memory leaves,
        uint256 peak
    ) public pure returns (MmrLeaf[] memory, MmrLeaf[] memory) {
        uint256 p = 0;
        for (;p < leaves.length; p++) {
            if (peak < leaves[p].mmr_pos) {
                break;
            }
        }

        uint256 len = p == 0 ? 0 : p;
        MmrLeaf[] memory left = new MmrLeaf[](len);
        MmrLeaf[] memory right = new MmrLeaf[](leaves.length - len);

        uint256 i = 0;
        while (i < left.length) {
            left[i] = leaves[i];
            i++;
        }

        uint256 j = 0;
        while (i < leaves.length) {
            right[j] = leaves[i];
            i++;
            j++;
        }

        return (left, right);
    }


    function getPeaks(uint256 mmrSize) public pure returns (uint256[] memory) {
        uint256 height;
        uint256 pos;
        (height, pos) = leftPeakHeightPos(mmrSize);
        uint256[] memory positions = new uint256[](height);
        uint256 p = 0;
        positions[p] = pos;
        p++;

        while (height > 0) {
            uint256 _height;
            uint256 _pos;
            (_height, _pos) = getRightPeak(height, pos, mmrSize);
            if (_height == 0 && _pos == 0) {
                break;
            }

            height = _height;
            pos = _pos;
            positions[p] = pos;
            p++;
        }

        // copy array to new one, sigh solidity.
        uint256 i = 0;
        uint256[] memory out = new uint256[](p);
        while (i < p) {
            out[i] = positions[i];
            i++;
        }

        return out;
    }

    function getRightPeak(uint256 height, uint256 pos, uint256 mmrSize) public pure returns (uint256, uint256) {
        pos += siblingOffset(height);

        while (pos > (mmrSize - 1)) {
            if (height == 0) {
                return (0, 0);
            }
            height -= 1;
            pos -= parentOffset(height);
        }

        return (height, pos);
    }

    function siblingOffset(uint256 height) public pure returns (uint256) {
        return (2 << height) - 1;
    }

    function parentOffset(uint256 height) public pure returns (uint256) {
        return 2 << height;
    }

    function leftPeakHeightPos(uint256 mmrSize) public pure returns (uint256, uint256) {
        uint256 height = 1;
        uint256 prevPos = 0;
        uint256 pos = getPeakPosByHeight(height);
        while (pos < mmrSize) {
            height += 1;
            prevPos = pos;
            pos = getPeakPosByHeight(height);
        }

        return (height - 1, prevPos);
    }

    function getPeakPosByHeight(uint256 height) public pure returns (uint256) {
        return (1 << (height + 1)) - 2;
    }

    function posToHeight(uint64 pos)  public pure returns (uint64) {
        pos += 1;

        while (!allOnes(pos)) {
            pos = jumpLeft(pos);
        }

        return (64 - countLeadingZeros(pos) - 1);

    }

    function allOnes(uint64 pos) public pure returns (bool) {
        return pos != 0 && countZeroes(pos) == countLeadingZeros(pos);
    }

    function jumpLeft(uint64 pos) public pure returns (uint64) {
        uint64 len = 64 - countLeadingZeros(pos);
        uint64 msb = uint64(1 << (len - 1));
        return (pos - (msb - 1));
    }

    function countLeadingZeros(uint64 num) public pure returns (uint64) {
        uint64 size = 64;
        uint64 count = 0;
        uint64  msb = uint64(1 << (size - 1));
        for (uint64 i = 0; i < size; i++) {
            if (((num << i) & msb) != 0) {
                break;
            }
            count++;

        }

        return count;
    }

    function countZeroes(uint64 num) public pure returns (uint256) {
        return 64 - countOnes(num);
    }

    function countOnes(uint64 num) public pure returns (uint64) {
        uint64 count = 0;

        while (num !=  0) {
            num &= (num - 1);
            count++;
        }

        return count;
    }

    // Integer log2
    // @returns floor(log2(x)) if x is nonzero, otherwise 0. This is the same
    //          as the location of the highest set bit.
    // Consumes 232 gas. This could have been an 3 gas EVM opcode though.
    function floorLog2(uint256 x) internal pure returns (uint256 r) {
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            r := or(r, shl(2, lt(0xf, shr(r, x))))
            r := or(r, shl(1, lt(0x3, shr(r, x))))
            r := or(r, lt(0x1, shr(r, x)))
        }
    }

    // functions in another library can't mutate local variables. sigh, solidity.
    function mergeArrays(
        Node[] memory out,
        Node[] memory arr1,
        Node[] memory arr2
    ) public pure {
        // merge the two arrays
        uint256 i = 0;
        while (i < arr1.length) {
            out[i] = arr1[i];
            i++;
        }

        uint256 j = 0;
        while (j < arr2.length) {
            out[i] = arr2[j];
            i++;
            j++;
        }
    }

    function quickSort(
        Node[] memory arr,
        uint256 left,
        uint256 right
    ) public pure {
        uint256 i = left;
        uint256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].k_index;
        while (i <= j) {
            while (arr[uint256(i)].k_index < pivot) i++;
            while (pivot < arr[uint256(j)].k_index) if (j > 0) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                arr[uint256(j)],
                arr[uint256(i)]
                );
                i++;
                if (j > 0) j--;
            }
        }
        if (left < j) quickSort(arr, left, j);
        if (i < right) quickSort(arr, i, right);
    }

    function quickSort(
        uint256[] memory arr,
        uint256 left,
        uint256 right
    ) public pure {
        uint256 i = left;
        uint256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)];
        while (i <= j) {
            while (arr[uint256(i)] < pivot) i++;
            while (pivot < arr[uint256(j)]) if (j > 0) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                arr[uint256(j)],
                arr[uint256(i)]
                );
                i++;
                if (j > 0) j--;
            }
        }
        if (left < j) quickSort(arr, left, j);
        if (i < right) quickSort(arr, i, right);
    }

    function quickSort(
        MmrLeaf[] memory arr,
        uint256 left,
        uint256 right
    ) public pure {
        uint256 i = left;
        uint256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)].mmr_pos;
        while (i <= j) {
            while (arr[uint256(i)].mmr_pos < pivot) i++;
            while (pivot < arr[uint256(j)].mmr_pos) if (j > 0) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                arr[uint256(j)],
                arr[uint256(i)]
                );
                i++;
                if (j > 0) j--;
            }
        }
        if (left < j) quickSort(arr, left, j);
        if (i < right) quickSort(arr, i, right);
    }
}