// Copyright (C) Polytope Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity ^0.8.17;

import {Test, console} from "forge-std/Test.sol";
import {MerkleMultiProof} from "../../src/MerkleMultiProof.sol";

contract MerkleMultiProofTest is Test {
    function CalculateRoot(
        bytes32[] memory proof,
        MerkleMultiProof.Leaf[] memory leaves,
        uint256 numLeaves
    ) public view returns (bytes32) {
        uint256 startGas = gasleft();
        bytes32 root = MerkleMultiProof.CalculateRoot(
            proof,
            leaves,
            numLeaves
        );
        uint256 gasUsed = startGas - gasleft();
        console.log(gasUsed);
        return root;
    }

    /**
     * @notice Duplicate leaf index with forged hash — the original exploit.
     *         Both leaves share position P; neither pairs as the other's
     *         sibling (pos ^ 1 != pos), and `_walk`'s `positions[0] != 1`
     *         short-circuit returned `hashes[0]` while silently discarding
     *         the forged climb. Must now revert with UnsortedLeaves.
     */
    function testDuplicateLeafIndex_ForgedHash() public {
        bytes32[] memory proof = new bytes32[](4);
        proof[0] = bytes32(uint256(0x1111));
        proof[1] = bytes32(uint256(0x2222));
        proof[2] = bytes32(uint256(0x3333));
        proof[3] = bytes32(uint256(0x4444));

        MerkleMultiProof.Leaf[] memory leaves = new MerkleMultiProof.Leaf[](2);
        leaves[0] = MerkleMultiProof.Leaf(0, bytes32(uint256(0xaaaa)));
        leaves[1] = MerkleMultiProof.Leaf(0, bytes32(uint256(0xdeadbeef))); // dup index

        vm.expectRevert(MerkleMultiProof.UnsortedLeaves.selector);
        this.CalculateRoot(proof, leaves, 4);
    }

    /**
     * @notice Duplicate leaf with identical hash is still malformed — reject it.
     */
    function testDuplicateLeafIndex_SameHash() public {
        bytes32[] memory proof = new bytes32[](4);
        proof[0] = bytes32(uint256(0x1111));
        proof[1] = bytes32(uint256(0x2222));
        proof[2] = bytes32(uint256(0x3333));
        proof[3] = bytes32(uint256(0x4444));

        MerkleMultiProof.Leaf[] memory leaves = new MerkleMultiProof.Leaf[](2);
        leaves[0] = MerkleMultiProof.Leaf(0, bytes32(uint256(0xaaaa)));
        leaves[1] = MerkleMultiProof.Leaf(0, bytes32(uint256(0xaaaa))); // same index & hash

        vm.expectRevert(MerkleMultiProof.UnsortedLeaves.selector);
        this.CalculateRoot(proof, leaves, 4);
    }

    /**
     * @notice Descending leaf order is unsupported — the `_walk` algorithm assumes
     *         strictly increasing indices so positions land in sorted order per level.
     */
    function testUnsortedLeaves_DescendingOrder() public {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = bytes32(uint256(0x1111));
        proof[1] = bytes32(uint256(0x2222));

        MerkleMultiProof.Leaf[] memory leaves = new MerkleMultiProof.Leaf[](2);
        leaves[0] = MerkleMultiProof.Leaf(2, bytes32(uint256(0xcccc)));
        leaves[1] = MerkleMultiProof.Leaf(1, bytes32(uint256(0xbbbb)));

        vm.expectRevert(MerkleMultiProof.UnsortedLeaves.selector);
        this.CalculateRoot(proof, leaves, 4);
    }
}
