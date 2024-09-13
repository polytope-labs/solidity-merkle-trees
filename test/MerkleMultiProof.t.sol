// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import "forge-std/Test.sol";

import "@openzeppelin/contracts/utils/math/Math.sol";
import "../src/MerkleMultiProof.sol";

contract MerkleMultiProofTest is Test {
    // needs a test method so that forge can detect it
    function testMerkleMultiProof() public {}

    function CalculateRoot(
        Node[][] memory proof,
        Node[] memory leaves
    ) public pure returns (bytes32) {
        return MerkleMultiProof.CalculateRoot(proof, leaves);
    }

    function CalculateRootSorted(
        Node[][] memory proof,
        Node[] memory leaves
    ) public pure returns (bytes32) {
        return MerkleMultiProof.CalculateRootSorted(proof, leaves);
    }

    function TreeHeight(uint256 leavesCount) public pure returns (uint256) {
        return MerkleMultiProof.TreeHeight(leavesCount);
    }
}
