// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./MerkleMultiProof.sol";
import "./MerkleMountainRange.sol";
import "./MerklePatricia.sol";
import "./trie/substrate/SubstrateTrieDB.sol";
import "./trie/NibbleSlice.sol";

contract MerkleTests is Test {
    function testCalculateRoot(Node[][] memory proof, Node[] memory leaves)
    public
    pure
    returns (bytes32)
    {
        return MerkleMultiProof.calculateRoot(proof, leaves);
    }

    function testMerklePatricia(bytes32 root, bytes[] memory proof, bytes[] memory keys)
    public
    returns (bytes[] memory)
    {
        SubstrateTrieDB trieDb = new SubstrateTrieDB(proof);
        return MerklePatricia.VerifyKeys(root, trieDb, keys);
    }

    function decodeNodeKind(bytes memory node) public returns (NodeKind memory) {
        bytes[] memory nodes = new bytes[](1);
        SubstrateTrieDB trieDb = new SubstrateTrieDB(nodes);
        return trieDb.decodeNodeKind(node);
    }

    function decodeNibbledBranch(bytes memory node) external returns (NibbledBranch memory) {
        bytes[] memory nodes = new bytes[](1);
        SubstrateTrieDB trieDb = new SubstrateTrieDB(nodes);
        return trieDb.decodeNibbledBranch(trieDb.decodeNodeKind(node));
    }

    function decodeLeaf(bytes memory node) external returns (Leaf memory) {
        bytes[] memory nodes = new bytes[](1);
        SubstrateTrieDB trieDb = new SubstrateTrieDB(nodes);
        return trieDb.decodeLeaf(trieDb.decodeNodeKind(node));
    }

    function nibbleLen(NibbleSlice memory nibble) public pure returns (uint256) {
        return NibbleSliceOps.len(nibble);
    }

    function mid(NibbleSlice memory self, uint256 i) public pure returns (NibbleSlice memory) {
        return NibbleSliceOps.mid(self, i);
    }

    function isNibbleEmpty(NibbleSlice memory self) public pure returns (bool) {
        return NibbleSliceOps.isEmpty(self);
    }

    function eq(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.eq(self, other);
    }

    function nibbleAt(NibbleSlice memory self, uint256 i) public pure returns (uint256) {
        return NibbleSliceOps.at(self, i);
    }

    function startsWith(NibbleSlice memory self, NibbleSlice memory other) public pure returns (bool) {
        return NibbleSliceOps.startsWith(self, other);
    }

    function commonPrefix(NibbleSlice memory self, NibbleSlice memory other) public pure returns (uint256) {
        return NibbleSliceOps.commonPrefix(self, other);
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

    function siblingIndices(uint256[] memory indices) public pure returns (uint256[] memory) {
        return MerkleMountainRange.siblingIndices(indices);
    }

    function mmrLeafToNode(MmrLeaf[] memory leaves) public pure returns (Node[] memory, uint256[] memory) {
        return MerkleMountainRange.mmrLeafToNode(leaves);
    }

    function calculateRoot(
        bytes32[] memory proof,
        MmrLeaf[] memory leaves,
        uint256 mmrSize
    ) public pure returns (bytes32) {
        return MerkleMountainRange.calculateRoot(proof, leaves, mmrSize);
    }
}
