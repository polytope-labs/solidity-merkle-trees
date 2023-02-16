pragma solidity ^0.8.17;

// SPDX-License-Identifier: Apache2

import "./NodeCodec.sol";
import "./NibbleSlice.sol";

/// This is an enum for the different node types.
struct Node {
    bool isEmpty;
    bool isLeaf;
    bool isExtension;
    bool isBranch;
    bool isNibbledBranch;
    bool isOpaqueBytes;

    bytes data;
}

struct NodeHandle {
    bool isHash;
    bytes32 hash;

    bool isInline;
    Node inLine;
}

struct Extension {
    NibbleSlice key;
    NodeHandle node;
}

struct Branch {
    NodeHandleOption value;
    NodeHandleOption[16] children;
}

struct NibbledBranch {
    NibbleSlice key;
    NodeHandleOption value;
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
    NibbleSlice key;
    NodeHandle value;
}
