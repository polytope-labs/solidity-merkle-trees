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

    /**
     * @notice Critical forgery: `_walk` terminates at the genuine root, discarding the
     *         forged leaf's partial subtree.
     *
     *         We manually build a genuine 4-leaf tree (leaves at positions 4..7):
     *
     *                       1 = root
     *                     /   \
     *                   2       3
     *                  / \     / \
     *                 4   5   6   7      n2 = H(a,b) at pos 2, n3 = H(c,d) at pos 3
     *                 a   b   c   d      root = H(n2,n3) at pos 1
     *
     *         A leafCount above 2^255 makes `firstLeafPos = 1 << _ceilLog2(leafCount) =
     *         1 << 256 = 0`, so leaf positions equal raw indices — freeing leaves from the
     *         leaf level. (Exactly `type(uint256).max` would instead overflow `lastValid`
     *         in `_walk` before it runs; any value in (2^255, ~2^256) reproduces the bug,
     *         so we use 2^255 + 1.)
     *
     *         The attacker proves the genuine first leaf `a` at position 4 AND appends a
     *         forged leaf at position 8 — a phantom child below position 4. `_walk` rebuilds
     *         the genuine branch (4 -> 2 -> 1 = root) and the `while (positions[0] != 1)`
     *         loop exits the instant it reaches the root, while the forged leaf's partial
     *         climb (8 -> 4 -> 2) is still in the set (`len == 2`). The old code returned
     *         `hashes[0]` (= the genuine root), so the forged leaf "verified" against it.
     *         Must now revert UnconsumedLeaves.
     */
    function testForgery_TerminateAtRoot_UnconsumedForgedSubtree() public {
        // Genuine 4-leaf tree, hashed per `_hashPair` (even position => keccak(current, sibling)).
        bytes32 a = keccak256("a");
        bytes32 b = keccak256("b");
        bytes32 c = keccak256("c");
        bytes32 d = keccak256("d");
        bytes32 n2 = keccak256(abi.encodePacked(a, b)); // position 2
        bytes32 n3 = keccak256(abi.encodePacked(c, d)); // position 3
        bytes32 root = keccak256(abi.encodePacked(n2, n3)); // position 1

        uint256 leafCount = (uint256(1) << 255) + 1; // => firstLeafPos = (1 << 256) = 0

        // Sanity: the honest proof of leaf `a` (position 4) rebuilds the genuine root.
        {
            MerkleMultiProof.Leaf[] memory genuine = new MerkleMultiProof.Leaf[](1);
            genuine[0] = MerkleMultiProof.Leaf(4, a);
            bytes32[] memory genuineProof = new bytes32[](2);
            genuineProof[0] = b; // sibling at position 5
            genuineProof[1] = n3; // uncle at position 3
            assertTrue(MerkleMultiProof.VerifyProof(root, genuineProof, genuine, leafCount));
        }

        // Forgery: genuine leaf at position 4 + forged leaf at position 8.
        MerkleMultiProof.Leaf[] memory leaves = new MerkleMultiProof.Leaf[](2);
        leaves[0] = MerkleMultiProof.Leaf(4, a); // genuine, position 4
        leaves[1] = MerkleMultiProof.Leaf(8, keccak256("forged")); // forged, position 8

        bytes32[] memory proof = new bytes32[](4);
        proof[0] = b; // genuine: pos 4 sibling -> n2
        proof[1] = keccak256("forged-sibling"); // forged climb (discarded by old code)
        proof[2] = n3; // genuine: pos 2 sibling -> root
        proof[3] = keccak256("forged-uncle"); // forged climb (discarded by old code)

        // Old behaviour: returned hashes[0] (= genuine root), forged subtree silently dropped.
        // Fixed behaviour: walk ends with len == 2, so it reverts.
        vm.expectRevert(abi.encodeWithSelector(MerkleMultiProof.UnconsumedLeaves.selector, uint256(2)));
        this.CalculateRoot(proof, leaves, leafCount);
    }
}
