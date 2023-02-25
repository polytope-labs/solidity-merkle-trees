pragma solidity ^0.8.17;

import "./trie/NodeCodec.sol";
import "./trie/Node.sol";
import "./trie/Option.sol";
import "./trie/NibbleSlice.sol";
import "./trie/TrieDB.sol";
import "./trie/substrate/SubstrateTrieDB.sol";

// SPDX-License-Identifier: Apache2

library MerklePatricia {
     /// @notice libraries in solidity can only have constant variables
     /// @dev MAX_TRIE_DEPTH, we don't explore deeply nested trie keys.
     uint256 internal constant MAX_TRIE_DEPTH = 50;

     /**
      * @notice Verify Keys
      * @param root hash of the merkle root
      * @param proof a list of proof nodes
      * @param keys a list of keys to verify
      * @return bytes[] a list of verified keys
      */
     function VerifySubstrateProof(bytes32 root, bytes[] memory proof,  bytes[] memory keys)
          public
          pure
          returns (bytes[] memory)
     {
          bytes[] memory values = new bytes[](keys.length);
          TrieNode[] memory nodes = new TrieNode[](proof.length);

          for (uint256 i = 0; i < proof.length; i++) {
               nodes[i] = TrieNode(keccak256(proof[i]), proof[i]);
          }

          for (uint256 i = 0; i < keys.length; i++) {
               NibbleSlice memory keyNibbles = NibbleSlice(keys[i], 0);
               NodeKind memory node = SubstrateTrieDB.decodeNodeKind(TrieDB.get(nodes, root));

               // worst case scenario, so we avoid unbounded loops
               for (uint256 j = 0; j < MAX_TRIE_DEPTH; j++) {
                    NodeHandle memory nextNode;

                    if (NodeCodec.isLeaf(node)) {
                         Leaf memory leaf = SubstrateTrieDB.decodeLeaf(node);
                         if (NibbleSliceOps.eq(leaf.key, keyNibbles)) {
                              values[i] = TrieDB.load(nodes, leaf.value);
                         }
                         break;
                    } else if (NodeCodec.isExtension(node)) {
                         Extension memory extension = SubstrateTrieDB.decodeExtension(node);
                         if (NibbleSliceOps.startsWith(keyNibbles, extension.key)) {
                              uint256 len = NibbleSliceOps.len(extension.key);
                              keyNibbles = NibbleSliceOps.mid(keyNibbles, len);
                              nextNode = extension.node;
                         } else {
                              break;
                         }
                    } else if (NodeCodec.isBranch(node)) {
                         Branch memory branch = SubstrateTrieDB.decodeBranch(node);
                         if (NibbleSliceOps.isEmpty(keyNibbles)) {
                              if (Option.isSome(branch.value)) {
                                   values[i] = TrieDB.load(nodes, branch.value.value);
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
                         NibbledBranch memory nibbled = SubstrateTrieDB.decodeNibbledBranch(node);
                         uint256 nibbledBranchKeyLength = NibbleSliceOps.len(nibbled.key);
                         if (!NibbleSliceOps.startsWith(keyNibbles, nibbled.key)) {
                              break;
                         }

                         if (NibbleSliceOps.len(keyNibbles) == nibbledBranchKeyLength) {
                              if (Option.isSome(nibbled.value)) {
                                   values[i] = TrieDB.load(nodes, nibbled.value.value);
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

                    node = SubstrateTrieDB.decodeNodeKind(TrieDB.load(nodes, nextNode));
               }
          }

          return values;
     }

     /**
      * @notice Verify child trie keys
      * @dev substrate specific method in order to verify keys in the child trie.
      * @param root hash of the merkle root
      * @param proof a list of proof nodes
      * @param keys a list of keys to verify
      * @param childInfo data that can be used to compute the root of the child trie
      * @return bytes[], a list of verified keys
      */
     function ReadChildProofCheck(bytes32 root, bytes[] memory proof, bytes[] memory keys, bytes memory childInfo)
          public
          pure
          returns (bytes[] memory)
     {
          // fetch the child trie root hash;
          bytes memory prefix = bytes(":child_storage:default:");
          bytes memory key = bytes.concat(prefix, childInfo);
          bytes[] memory _keys = new bytes[](1);
          _keys[0] = key;
          bytes[] memory values  = VerifySubstrateProof(root, proof, _keys);

          bytes32 childRoot = bytes32(values[0]);
          require(childRoot != bytes32(0), "Invalid child trie proof");
          
          return VerifySubstrateProof(childRoot, proof, keys);
     }
}