pragma solidity ^0.8.17;

import "./ParachainHashDB.sol";
import "./NodeCodec.sol";
import "./NibbleSlice.sol";
import "./HashDB.sol";

// SPDX-License-Identifier: Apache2

library MerklePatricia {
     function Verify(bytes32 root, HashDB hashDB, bytes[] keys)
     public
     pure
     returns (bytes[] memory)
     {
          bytes[] values = new bytes[](keys.length);

          for (uint256 i = 0; i < keys.length; i++) {
               NibbleSlice partial = new NibbleSlice(keys[i]);
               Node node = hashDB.get(root);

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < proof.length; j++) {
                    NodeHandle nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf leaf = NodeCodec.asLeaf(node);
                         if (leaf.partial == partial) {
                              values[i] = leaf.value;
                         } else {
                              // todo: is this necessary?
                              values[i] = bytes(0);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension ext = NodeCodec.asExtension(node);
                         if (partial.startWith(ext.partial)) {
                              uint256 len = ext.partial.len();
                              partial = partial.mid(len);
                              key_nibbles += len;
                         } else {
                              // todo: is this necessary?
                              values[i] = bytes(0);
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch branch = NodeCodec.asBranch(node);
                         if (partial.is_empty()) {
                              if (branch.value.isSome()) {
                                   values[i] = branch.value.unwrap();
                              } else {
                                   // todo: is this necessary?
                                   values[i] = bytes(0);
                                   break;
                              }
                         } else {
                              NodeHandleOption handle = branch.children.get(partial.at(0));
                              if (handle.isSome()) {
                                   partial = partial.mid(1);
                                   nextNode = handle.unwrap();
                              } else {
                                   // todo: is this necessary?
                                   values[i] = bytes(0);
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isNibbledBranch(node)) {
                         NibbledBranch nibbled = NodeHandleCodec.asNibbledBranch(nextNode);
                         if (!partial.startsWith(nibbled.partial)) {
                              // todo: is this necessary?
                              values[i] = bytes(0);
                              break;
                         }

                         if (partial.len() == nibbled.partial.len()) {
                              values[i] = nibbled.value;
                         } else {
                              NodeHandleOption handle = nibbled.children.get(nibbled.partial.len());
                              if (handle.isSome()) {
                                   partial = partial.mid(nibbled.partial.len() + 1);
                                   nextNode = handle.unwrap();
                              } else {
                                   // todo: is this necessary?
                                   values[i] = bytes(0);
                                   break;
                              }
                         }
                    }  else if (NodeCodec.isEmpty(node)) {
                         // todo: is this necessary?
                         values[i] = bytes(0);
                         break;
                    }

                    if (NodeHandleCodec.isHash(nextNode)) {
                         bytes32 hash = NodeHandleCodec.asHash(nextNode);
                         node = hashDB.get(hash);
                    } else if (NodeCodec.isInline(nextNode)) {
                         encoded = NodeHandleCodec.asInline(nextNode);
                    }
               }
          }

          return values;
     }
}