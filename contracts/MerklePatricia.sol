pragma solidity ^0.8.17;

import "./trie/NodeCodec.sol";
import "./trie/Option.sol";
import "./trie/NibbleSlice.sol";
import "./trie/TrieDB.sol";

// SPDX-License-Identifier: Apache2

library MerklePatricia {
     // so we don't explore deeply nested trie keys.
     uint256 internal constant MAX_TRIE_DEPTH = 50;

     function VerifyKeys(bytes32 root, TrieDB trieDb, bytes[] memory keys)
          public
          returns (bytes[] memory)
     {
          bytes[] memory values = new bytes[](keys.length);

          for (uint256 i = 0; i < keys.length; i++) {
               NibbleSlice memory keyNibbles = NibbleSlice(keys[i], 0);
               NodeKind memory node = trieDb.decodeNodeKind(trieDb.get(root));

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < MAX_TRIE_DEPTH; j++) {
                    NodeHandle memory nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf memory leaf = trieDb.decodeLeaf(node);
                         if (NibbleSliceOps.eq(leaf.key, keyNibbles)) {
                              values[i] = trieDb.load(leaf.value);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension memory extension = trieDb.decodeExtension(node);
                         if (NibbleSliceOps.startsWith(keyNibbles, extension.key)) {
                              uint256 len = NibbleSliceOps.len(extension.key);
                              keyNibbles = NibbleSliceOps.mid(keyNibbles, len);
                              nextNode = extension.node;
                         } else {
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch memory branch = trieDb.decodeBranch(node);
                         if (NibbleSliceOps.isEmpty(keyNibbles)) {
                              if (Option.isSome(branch.value)) {
                                   values[i] = trieDb.load(branch.value.value);
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
                         NibbledBranch memory nibbled = trieDb.decodeNibbledBranch(node);
                         uint256 nibbledBranchKeyLength = NibbleSliceOps.len(nibbled.key);
                         if (!NibbleSliceOps.startsWith(keyNibbles, nibbled.key)) {
                              break;
                         }

                         if (NibbleSliceOps.len(keyNibbles) == nibbledBranchKeyLength) {
                              if (Option.isSome(nibbled.value)) {
                                   values[i] = trieDb.load(nibbled.value.value);
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

                    node = trieDb.decodeNodeKind(trieDb.load(nextNode));
               }
          }

          return values;
     }

     // substrate specific method in order to verify keys in the child trie.
     function ReadChildProofCheck(bytes32 root, TrieDB trieDB, bytes memory childInfo, bytes[] memory keys)
          public
          returns (bytes[] memory)
     {
          // fetch the child trie root hash;
          bytes memory prefix = bytes(":child_storage:default:");
          bytes memory key = bytes.concat(prefix, childInfo);
          bytes[] memory _keys = new bytes[](1);
          _keys[0] = key;
          bytes[] memory values  = VerifyKeys(root, trieDB, _keys);

          bytes32 childRoot = bytes32(values[0]);
          require(childRoot != bytes32(0), "Invalid child trie proof");
          
          return VerifyKeys(childRoot, trieDB, keys);
     }
}