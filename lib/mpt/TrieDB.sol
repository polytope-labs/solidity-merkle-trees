pragma solidity ^0.8.17;

import "./NodeCodec.sol";
import "./HashDB.sol";
import "./Option.sol";
import "./NibbleSlice.sol";

// SPDX-License-Identifier: Apache2

library TrieDB {
     function ReadProofCheck(bytes32 root, HashDB hashDB, bytes[] keys)
     public
     pure
     returns (bytes[] memory)
     {
          bytes[] values = new bytes[](keys.length);

          for (uint256 i = 0; i < keys.length; i++) {
               NibbleSlice keyNibbles = NibbleSlice(keys[i]);
               Node node = hashDB.get(root);

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < hashDB.length(); j++) {
                    NodeHandle nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf leaf = NodeCodec.asLeaf(node);
                         if (NibbleSliceOps.eq(leaf.key, keyNibbles)) {
                              values[i] = NodeCodec.loadValue(leaf.value, hashDB);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension extension = NodeCodec.asExtension(node);
                         if (NibbleSliceOps.startWith(keyNibbles, extension.key)) {
                              uint256 len = NibbleSliceOps.len(extension.key);
                              keyNibbles = NibbleSliceOps.mid(keyNibbles, len);
                              nextNode = extension.node;
                         } else {
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch branch = NodeCodec.asBranch(node);
                         if (NibbleSliceOps.isEmpty(keyNibbles)) {
                              if (Option.isSome(branch.value)) {
                                   values[i] = NodeCodec.loadValue(branch.value, hashDB);
                              }
                              break;
                         } else {
                              NodeHandleOption handle = branch.children[NibbleSliceOps.at(keyNibbles, 0)];
                              if (Option.isSome(handle)) {
                                   keyNibbles = NibbleSliceOps.mid(keyNibbles, 1);
                                   nextNode = handle.value;
                              } else {
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isNibbledBranch(node)) {
                         NibbledBranch nibbled = NodeCodec.asNibbledBranch(nextNode);
                         uint256 nibbledBranchKeyLength = NibbleSliceOps.len(nibbled.key);
                         if (!NibbleSliceOps.startsWith(keyNibbles, nibbled.key)) {
                              break;
                         }

                         if (NibbleSliceOps.len(keyNibbles) == nibbledBranchKeyLength) {
                              if (Option.isSome(nibbled.value)) {
                                   values[i] = NodeCodec.loadValue(nibbled.value, hashDB);
                              }
                              break;
                         } else {
                              uint256 index = NibbleSliceOps.at(keyNibbles, nibbledBranchKeyLength);
                              NodeHandleOption handle = nibbled.children[index];
                              if (Option.isSome(handle)) {
                                   keyNibbles = NibbleSliceOps.mid(keyNibbles, nibbledBranchKeyLength + 1);
                                   nextNode = handle.value;
                              } else {
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isEmpty(node)) {
                         break;
                    }

                    if (NodeCodec.isHash(nextNode)) {
                         node = hashDB.get(NodeCodec.asHash(nextNode));
                    } else if (NodeCodec.isInline(nextNode)) {
                         node = NodeCodec.asInline(nextNode);
                    }
               }
          }

          return values;
     }

     function ReadChildProofCheck(bytes32 root, HashDB hashDB, bytes childInfo, bytes[] keys)
     public
     pure
     returns (bytes[] memory)
     {
          // fetch the child trie root hash;
          bytes key = ChildRootKey(childInfo);
          bytes[] values  = ReadProofCheck(root, hashDB, [key]);
          bytes32 childRoot = values[0]; // todo: needs to be converted to bytes32
          require(childRoot != bytes32(0), "Invalid child trie proof");
          
          return ReadProofCheck(childRoot, hashDB, keys);
     }

     function ChildRootKey(bytes info) public pure returns (bytes memory)  {
          bytes prefix = bytes(":child_storage:default:");
          return bytes.concat(prefix, info);
     }
}