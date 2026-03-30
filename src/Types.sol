// Copyright (C) Polytope Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
pragma solidity ^0.8.17;

// Outcome of a successfully verified merkle-patricia proof
struct StorageValue {
    // the storage key
    bytes key;
    // the encoded value
    bytes value;
}

/// @title A representation of a Merkle tree node
struct Node {
    // Distance of the node to the leftmost node
    uint256 nodeIndex;
    // A hash of the node itself
    bytes32 node;
}

/// @title A representation of a MerkleMountainRange leaf
struct MmrLeaf {
    // 1-based tree position of the node within its subtree peak
    uint256 nodeIndex;
    // The 0-based index of the leaf in the tree
    uint256 leafIndex;
    // The hash of the leaf
    bytes32 hash;
}

struct Iterator {
    uint256 offset;
    bytes32[] data;
}
