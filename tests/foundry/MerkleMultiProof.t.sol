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
}
