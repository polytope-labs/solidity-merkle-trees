// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./MerkleMultiProof.sol";
import "./MerkleMountainRange.sol";

contract MerkleMultiProofTest is Test {
    function testCalculateRoot(Node[][] calldata proof)
    public
    pure
    returns (bytes32)
    {
        return MerkleMultiProof.calculateRoot(proof);
    }

    function countZeroes(uint64 num) public pure returns (uint256) {
        return MerkleMountainRange.countZeroes(num);
    }

    function countLeadingZeros(uint64 num) public pure returns (uint256) {
        return MerkleMountainRange.countLeadingZeros(num);
    }

    function countOnes(uint64 num) public pure returns (uint256) {
        return MerkleMountainRange.countOnes(num);
    }

    function posToHeight(uint64 num) public pure returns (uint256) {
        return MerkleMountainRange.posToHeight(num);
    }

    function getPeaks(uint64 num) public pure returns (uint256[] memory) {
        return MerkleMountainRange.getPeaks(num);
    }

    function leavesForPeak(MmrLeaf[] memory leaves, uint64 peak) public pure returns (MmrLeaf[] memory, MmrLeaf[] memory) {
        return MerkleMountainRange.leavesForPeak(leaves, peak);
    }

    function difference(uint256[] memory left, uint256[] memory right) public pure returns (uint256[] memory) {
        return MerkleMountainRange.difference(left, right);
    }

    function removeDuplicates(uint256[] memory arr) public pure returns (uint256[] memory) {
        return MerkleMountainRange.removeDuplicates(arr);
    }


    function siblingIndices(uint256[] memory indices) public pure returns (uint256[] memory) {
        return MerkleMountainRange.siblingIndices(indices);
    }

    function mmrLeafToNode(MmrLeaf[] memory leaves) public pure returns (Node[] memory, uint256[] memory) {
        return MerkleMountainRange.mmrLeafToNode(leaves);
    }

    function calculateRoot(
        MmrLeaf[] memory leaves,
        uint256 mmrSize,
        bytes32[] memory proof
    ) public pure returns (bytes32) {
        return MerkleMountainRange.calculateRoot(leaves, mmrSize, proof);
    }
}
