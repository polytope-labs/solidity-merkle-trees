pragma solidity ^0.8.17;

import "./NodeCodec.sol";
import "./HashDB.sol";
import "./Option.sol";
import "./NibbleSlice.sol";

// SPDX-License-Identifier: Apache2

library TrieDB {
     function ReadProofCheck(bytes32 root, HashDB hashDB, bytes[] memory keys)
     public
     pure
     returns (bytes[] memory)
     {
          bytes[] memory values = new bytes[](keys.length);

          for (uint256 i = 0; i < keys.length; i++) {
               NibbleSlice memory keyNibbles = NibbleSlice(keys[i], 0);
               Node memory node = hashDB.get(root);

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < hashDB.length(); j++) {
                    NodeHandle memory nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf memory leaf = NodeCodec.decodeLeaf(node);
                         if (NibbleSliceOps.eq(leaf.key, keyNibbles)) {
                              values[i] = NodeCodec.loadValue(leaf.value, hashDB);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension memory extension = NodeCodec.decodeExtension(node);
                         if (NibbleSliceOps.startsWith(keyNibbles, extension.key)) {
                              uint256 len = NibbleSliceOps.len(extension.key);
                              keyNibbles = NibbleSliceOps.mid(keyNibbles, len);
                              nextNode = extension.node;
                         } else {
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch memory branch = NodeCodec.decodeBranch(node);
                         if (NibbleSliceOps.isEmpty(keyNibbles)) {
                              if (Option.isSome(branch.value)) {
                                   values[i] = NodeCodec.loadValue(branch.value.value, hashDB);
                              }
                              break;
                         } else {
                              NodeHandleOption memory handle = branch.children[NibbleSliceOps.at(keyNibbles, 0)];
                              if (Option.isSome(handle)) {
                                   keyNibbles = NibbleSliceOps.mid(keyNibbles, 1);
                                   nextNode = handle.value;
                              } else {
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isNibbledBranch(node)) {
                         NibbledBranch memory nibbled = NodeCodec.decodeNibbledBranch(node);
                         uint256 nibbledBranchKeyLength = NibbleSliceOps.len(nibbled.key);
                         if (!NibbleSliceOps.startsWith(keyNibbles, nibbled.key)) {
                              break;
                         }

                         if (NibbleSliceOps.len(keyNibbles) == nibbledBranchKeyLength) {
                              if (Option.isSome(nibbled.value)) {
                                   values[i] = NodeCodec.loadValue(nibbled.value.value, hashDB);
                              }
                              break;
                         } else {
                              uint256 index = NibbleSliceOps.at(keyNibbles, nibbledBranchKeyLength);
                              NodeHandleOption memory handle = nibbled.children[index];
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
                         node = hashDB.get(nextNode.hash);
                    } else if (NodeCodec.isInline(nextNode)) {
                         node = nextNode.inLine;
                    }
               }
          }

          return values;
     }

     function ReadChildProofCheck(bytes32 root, HashDB hashDB, bytes memory childInfo, bytes[] memory keys)
     public
     pure
     returns (bytes[] memory)
     {
          // fetch the child trie root hash;
          bytes memory key = ChildRootKey(childInfo);
          bytes[] memory values  = ReadProofCheck(root, hashDB, [key]);
          bytes32 childRoot = bytes32(values[0]);
          require(childRoot != bytes32(0), "Invalid child trie proof");
          
          return ReadProofCheck(childRoot, hashDB, keys);
     }

     function ChildRootKey(bytes memory info) public pure returns (bytes memory)  {
          bytes memory prefix = bytes(":child_storage:default:");
          return bytes.concat(prefix, info);
     }
}