// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "../contracts/MerkleMultiProof.sol";

contract MerkleMultiProofTest is Test {
    // needs a test method so that forge can detect it
    function testMerkleMultiProof() public {}

    function CalculateRoot(Node[][] memory proof, Node[] memory leaves)
    public
    pure
    returns (bytes32)
    {
        return MerkleMultiProof.CalculateRoot(proof, leaves);
    }
}