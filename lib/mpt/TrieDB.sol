pragma solidity ^0.8.17;

import "./NodeCodec.sol";
import "./HashDB.sol";
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
               NibbleSlice partial = NibbleSlice(keys[i]);
               Node node = hashDB.get(root);

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < proof.length; j++) {
                    NodeHandle nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf leaf = NodeCodec.asLeaf(node);
                         if (NodeSliceOps.eq(leaf.partial, partial)) {
                              values[i] = NodeCodec.loadValue(leaf.value, hashDB);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension extension = NodeCodec.asExtension(node);
                         if (NibbleSliceOps.startWith(partial, extension.partial)) {
                              uint256 len = NibbleSliceOps.len(extension.partial);
                              partial = NibbleSliceOps.mid(partial, len);
                              key_nibbles += len;
                              nextNode = extension.node;
                         } else {
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch branch = NodeCodec.asBranch(node);
                         if (NibbleSliceOps.isEmpty(partial)) {
                              if (Option.isSome(branch.value)) {
                                   values[i] = NodeCodec.loadValue(branch.value, hashDB);
                              }
                              break;
                         } else {
                              NodeHandleOption handle = branch.children[NibbleSliceOps.at(partial, 0)];
                              if (Option.isSome(handle)) {
                                   partial = NibbleSliceOps.mid(partial, 1);
                                   nextNode = handle.value;
                              } else {
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isNibbledBranch(node)) {
                         NibbledBranch nibbled = NodeCodec.asNibbledBranch(nextNode);
                         if (!NibbleSliceOps.startsWith(partial, nibbled.partial)) {
                              break;
                         }

                         if (NibbleSliceOps.len(partial) == NibbleSliceOps.len(nibbled.partial)) {
                              if (Option.isSome(nibbled.value)) {
                                   values[i] = NodeCodec.loadValue(nibbled.value, hashDB);
                              }
                              break;
                         } else {
                              NodeHandleOption handle = nibbled.children[NibbleSliceOps.len(nibbled.partial)];
                              if (Option.isSome(handle)) {
                                   partial = NibbleSliceOps.mid(partial, NibbleSliceOps.len(nibbled.partial) + 1);
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
          bytes[] values  = ReadProofCheck(root, hashDB, key);
          require(values.length == 1, "Invalid child trie proof");
          bytes32 childRoot = values[0]; // todo: needs to be converted to bytes32
          return ReadProofCheck(childRoot, hashDB, keys);
     }

     function ChildRootKey(bytes info) public pure returns (bytes memory)  {
          bytes prefix = bytes(":child_storage:default:");
          bytes childRootKey = new bytes[](prefix.length + info.length);
          // todo: add prefix & info to childRootKey
          return childRootKey;
     }
}