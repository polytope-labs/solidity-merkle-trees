pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

import "./NodeCodec.sol";
import "./NibbleSlice.sol";

/// This is an enum for the different node types.
struct Node {
    bool isLeaf;
    Leaf leaf;

    bool isExtension;
    Extension extension;

    bool isBranch;
    Branch branch;

    bool isNibbledBranch;
    NibbledBranch nibbledBranch;
}

struct NodeHandle {
    bool isHash;
    bytes32 hash;

    bool isInline;
    Node inline;
}

struct Extension {
    NibbleSlice partial;
    NodeHandle node;
}

struct Branch {
    ValueOption value;
    NodeHandleOption[16] children;
}

struct NibbledBranch {
    NibbleSlice partial;
    ValueOption value;
    NodeHandleOption[16] children;
}

struct ValueOption {
    bool isSome;
    bytes value;
}

struct NodeHandleOption {
    bool isSome;
    NodeHandle value;
}

struct Leaf {
    NibbleSlice partial;
    bytes value;
}
