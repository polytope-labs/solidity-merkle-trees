// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/MerkleMultiProof.sol";

contract MerkleMultiProofTest is Test {
    function testVerify() public {
        bytes32 root = 0x72b0acd7c302a84f1f6b6cefe0ba7194b7398afb440e1b44a9dbbe270394ca53;
        Node[] memory empty;
        Node[][] memory proof = new Node[][](9);

        Node[] memory layer1 = new Node[](8);
        layer1[0] = Node(
            0,
            0x1a8da6deeedf22a65b8a552ec76a1f7ef67907c1f41c9279981423911e1bb742
        );
        layer1[1] = Node(
            1,
            0x00540198a1ef6f4ee4b6938be5cacf3b33d8988ee8d5f90044e6932b451e30b0
        );
        layer1[2] = Node(
            2,
            0xeabb03c592af442325d97bf94bd10f1054895a02b741086eab60b02037e67bd7
        );
        layer1[3] = Node(
            3,
            0xfdc99e493de3ae376733f5d181fa7b8b18c1dfc6503119597f40215217289e8e
        );
        layer1[4] = Node(
            4,
            0xaa856382eb8954abe5409552dee37ab9177a00413ae34b6cf82988ce8d5a48d2
        );
        layer1[5] = Node(
            5,
            0x5ad899e759ebee07febeff98964d18621638458fbf6a95c17252c4c0a3d2cfe5
        );
        layer1[6] = Node(
            8,
            0x2d858e75ddaf4da28de6af3d4d4393d9018e2bf8dc8d79de7aa200b27b1c25ea
        );
        layer1[7] = Node(
            9,
            0x736ad2a3e8190028a3a89933f92ea7bb0fc2616f3972a64380a2513c8e0d5e43
        );

        Node[] memory layer2 = new Node[](2);
        layer2[0] = Node(
            3,
            0xe93e19056274e1c32599c86abfdee9354b20ed6d303df150cd49864ae85fd29a
        );
        layer2[1] = Node(
            5,
            0x0962f26a7a55770de9b5b7477317cd8f0dd28cbc4e793792c8f0d93ef0029aa1
        );

        Node[] memory layer3 = new Node[](1);
        layer3[0] = Node(
            3,
            0x62f3ed9d0b006fae872c2fe620202be7e16b741232c9b7641a134915a79fa64e
        );

        Node[] memory layer5 = new Node[](1);
        layer5[0] = Node(
            1,
            0x303b91179fa7f87a1d8381670a67ccab7c0a5e7d6797bbb8270efb8759b5876c
        );

        Node[] memory layer6 = new Node[](1);
        layer6[0] = Node(
            1,
            0x48459896facce34edda5a7bbc502c1436a7b21bb6eafd4e234b938e7d8d814a2
        );
 
        Node[] memory layer7 = new Node[](1);
        layer7[0] = Node(
            1,
            0x20d34143d0be76f1271beac3039a896a97fa4aacc7d36dc6942ec9735cc18873
        );

        Node[] memory layer8 = new Node[](1);
        layer8[0] = Node(
            1,
            0x5ab43b8b43d9cac8d1bfeddb9d622f56027ada027d19f53224cc35e993e65240
        );

        proof[0] = layer1;
        proof[1] = layer2;
        proof[2] = layer3;
        proof[3] = empty;
        proof[4] = layer5;
        proof[5] = layer6;
        proof[6] = layer7;
        proof[7] = layer8;
        proof[8] = empty;
        
        assertEq(MerkleMultiProof.calculateRoot(proof), root);
    }
}
