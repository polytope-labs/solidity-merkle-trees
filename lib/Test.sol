// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "./MerkleMultiProof.sol";
import "./MerkleMountainRange.sol";
import "./MerklePatricia.sol";
import "./trie/substrate/SubstrateTrieDB.sol";
import "./trie/NibbleSlice.sol";

contract MerkleTests is Test {
    function CalculateRoot(Node[][] memory proof, Node[] memory leaves)
    public
    pure
    returns (bytes32)
    {
        return MerkleMultiProof.calculateRoot(proof, leaves);
    }

    function testMerklePatricia()
    public
    {

        bytes[] memory keys = new bytes[](1);
        keys[0] = hex"f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb";

        bytes[] memory proof = new bytes[](2);
        proof[0] = hex"802e98809b03c6ae83e3b70aa89acfe0947b3a18b5d35569662335df7127ab8fcb88c88780e5d1b21c5ecc2891e3467f6273f27ce2e73a292d6b8306197edfa97b3d965bd080c51e5f53a03d92ea8b2792218f152da738b9340c6eeb08581145825348bbdba480ad103a9320581c7747895a01d79d2fa5f103c4b83c5af10b0a13bc1749749523806eea23c0854ced8445a3338833e2401753fdcfadb3b56277f8f1af4004f73719806d990657a5b5c3c97b8a917d9f153cafc463acd90592f881bc071d6ba64e90b380346031472f91f7c44631224cb5e61fb29d530a9fafd5253551cbf43b7e97e79a";
        proof[1] = hex"9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb2035e90c7f86010000";

        bytes32 root = hex"6b5710000eccbd59b6351fc2eb53ff2c1df8e0f816f7186ddd309ca85e8798dd";
        SubstrateTrieDB trieDb = new SubstrateTrieDB(proof);
        bytes memory value = MerklePatricia.VerifyKeys(root, trieDb, keys)[0];
        console.logBytes(value);
    }

    function VerifyKeys(bytes32 root, bytes[] memory proof, bytes[] memory keys)
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
