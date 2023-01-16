// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./MerkleMultiProof.sol";

contract MerkleMultiProofTest is Test {
    function testCalculateRoot(Node[][] calldata proof)
    public
    pure
    returns (bytes32)
    {
        return MerkleMultiProof.calculateRoot(proof);
    }
}
