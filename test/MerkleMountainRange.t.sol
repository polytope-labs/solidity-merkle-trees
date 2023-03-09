// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../src/MerkleMountainRange.sol";

contract MerkleMountainRangeTest is Test {
    // needs a test method so that forge can detect it
    function testMerkleMountainRange() public {}

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

    function leavesForPeak(MmrLeaf[] memory leaves, uint64 peak)
        public
        pure
        returns (MmrLeaf[] memory, MmrLeaf[] memory)
    {
        return MerkleMountainRange.leavesForPeak(leaves, peak);
    }

    function difference(uint256[] memory left, uint256[] memory right) public pure returns (uint256[] memory) {
        return MerkleMountainRange.difference(left, right);
    }

    function siblingIndices(uint256[] memory indices) public pure returns (uint256[] memory) {
        return MerkleMountainRange.siblingIndices(indices);
    }

    function mmrLeafToNode(MmrLeaf[] memory leaves) public pure returns (Node[] memory, uint256[] memory) {
        return MerkleMountainRange.mmrLeafToNode(leaves);
    }

    function leafIndexToPos(uint64 index) public pure returns (uint64) {
        return MerkleMountainRange.leafIndexToPos(index);
    }

    function leafIndexToMmrSize(uint64 index) public pure returns (uint64) {
        return MerkleMountainRange.leafIndexToMmrSize(index);
    }

    function CalculateRoot(bytes32[] memory proof, MmrLeaf[] memory leaves, uint256 mmrSize)
        public
        pure
        returns (bytes32)
    {
        return MerkleMountainRange.CalculateRoot(proof, leaves, mmrSize);
    }
}
