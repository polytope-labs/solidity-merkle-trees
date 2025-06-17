// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

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

    function CalculateBalancedRoot(
        Node[] memory proof,
        Node[] memory leaves,
        uint256 numLeaves
    ) public view returns (bytes32) {
        uint256 startGas = gasleft();
        bytes32 root = MerkleMultiProof.CalculateBalancedRoot(
            proof,
            leaves,
            numLeaves
        );
        uint256 gasUsed = startGas - gasleft();
        console.log(gasUsed);
        return root;
    }

    function TreeHeight(uint256 leavesCount) public pure returns (uint256) {
        return MerkleMultiProof.TreeHeight(leavesCount);
    }
}
