use ethers::utils::keccak256;
use primitive_types::H256;
use std::collections::{BTreeMap, HashSet};

/// A node in the merkle tree with its position and hash value
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    /// Hash value of the node
    pub hash: H256,
    /// Position in the tree (1-based indexing)
    /// For a node at position n:
    /// - Left child is at 2n
    /// - Right child is at 2n + 1
    pub position: usize,
}

/// Error types for merkle tree operations
#[derive(Debug)]
pub enum MerkleError {
    /// Tree cannot be empty
    EmptyTree,
    /// Index out of bounds
    InvalidIndex(usize),
    /// Invalid proof structure
    InvalidProof(&'static str),
}

/// A merkle tree implementation where nodes are identified by their position
/// in a complete binary tree. The root is at position 1, and for any node
/// at position n:
/// - Its left child is at position 2n
/// - Its right child is at position 2n + 1
pub struct PositionalMerkleTree {
    /// Maps positions to nodes
    nodes: BTreeMap<usize, Node>,
    /// Number of actual leaves
    leaf_count: usize,
    /// Height of the tree
    height: usize,
    /// Position of first leaf
    first_leaf_pos: usize,
}

pub fn tree_height(num_leaves: u64) -> u64 {
    let mut height = 0;
    let mut nodes = num_leaves;
    while nodes > 1 {
        height += 1;
        nodes = (nodes + 1) / 2;
    }
    height
}

fn optimized_hash(left: H256, right: H256) -> H256 {
    H256(keccak256(&[left.as_bytes(), right.as_bytes()].concat()))
}

pub fn calculate_balanced_root(
    proof: &[Node],
    leaves: &[Node],
    num_leaves: u64,
) -> Result<H256, String> {
    let mut p = 0;
    let mut f = 0;
    let mut h = tree_height(num_leaves);
    dbg!(h);
    let mut flattened = std::iter::repeat(Node::default())
        .take(2usize.pow((h - 1) as u32))
        .collect::<Vec<_>>();

    // Process leaves
    let mut l = 0;
    while l < leaves.len() {
        if leaves[l].position % 2 == 0 {
            if p < proof.len() && proof[p].position == leaves[l].position + 1 {
                // Next sibling is in proof
                let node = Node {
                    hash: optimized_hash(leaves[l].hash, proof[p].hash),
                    position: leaves[l].position / 2,
                };
                flattened[f] = node;
                f += 1;
                p += 1;
            } else if l + 1 < leaves.len() && leaves[l + 1].position == leaves[l].position + 1 {
                // Next sibling must be in leaves
                let node = Node {
                    hash: optimized_hash(leaves[l].hash, leaves[l + 1].hash),
                    position: leaves[l].position / 2,
                };
                flattened[f] = node;
                f += 1;
                l += 1;
            } else {
                let node = Node { hash: leaves[l].hash, position: leaves[l].position / 2 };
                flattened[f] = node;
                f += 1;
                l += 1;
            }
        } else {
            if p < proof.len() && proof[p].position == leaves[l].position - 1 {
                // Next sibling is in proof
                let node = Node {
                    hash: optimized_hash(proof[p].hash, leaves[l].hash),
                    position: proof[p].position / 2,
                };
                flattened[f] = node;
                f += 1;
                p += 1;
            } else if l + 1 < leaves.len() && leaves[l + 1].position == leaves[l].position - 1 {
                // Next sibling must be in leaves
                let node = Node {
                    hash: optimized_hash(leaves[l + 1].hash, leaves[l].hash),
                    position: leaves[l + 1].position / 2,
                };
                flattened[f] = node;
                f += 1;
                l += 1;
            } else {
                return Err(format!("{} Leaf missing left sibling node", leaves[l].position));
            }
        }
        l += 1;
    }

    // We've processed all leaves and are moving up the tree
    h -= 1;

    while flattened[0].position != 1 {
        let mut r = 0;
        let mut w = 0;

        while r < flattened.len() {
            if flattened[r].position == 0 ||
                flattened[r].position >= 2u64.pow((h + 1) as u32) as usize
            {
                // Moving on up
                if h != 0 {
                    h -= 1;
                }
                r = 0;
                w = 0;
                break;
            }

            if flattened[r].position % 2 == 0 {
                if p < proof.len() && proof[p].position == flattened[r].position + 1 {
                    // Next sibling is in proof
                    let node = Node {
                        hash: optimized_hash(flattened[r].hash, proof[p].hash),
                        position: flattened[r].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    p += 1;
                } else if r + 1 < flattened.len() &&
                    flattened[r + 1].position == flattened[r].position + 1
                {
                    // Next sibling must be in flattened
                    let node = Node {
                        hash: optimized_hash(flattened[r].hash, flattened[r + 1].hash),
                        position: flattened[r].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                } else {
                    let node =
                        Node { hash: flattened[r].hash, position: flattened[r].position / 2 };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                }
            } else {
                if p < proof.len() && proof[p].position == flattened[r].position - 1 {
                    // Next sibling is in proof
                    let node = Node {
                        hash: optimized_hash(proof[p].hash, flattened[r].hash),
                        position: proof[p].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    p += 1;
                } else if r + 1 < flattened.len() &&
                    flattened[r + 1].position == flattened[r].position - 1
                {
                    // Next sibling must be in flattened
                    let node = Node {
                        hash: optimized_hash(flattened[r + 1].hash, flattened[r].hash),
                        position: flattened[r + 1].position / 2,
                    };
                    flattened[w] = node;
                    w += 1;
                    r += 1;
                } else {
                    return Err(
                        format!("Node {} missing left sibling node", flattened[r].position,),
                    );
                }
            }
            r += 1;
        }
    }

    Ok(flattened[0].hash)
}

impl PositionalMerkleTree {
    /// Creates a new merkle tree from a list of leaf hashes
    pub fn new(leaves: &[H256]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        let leaf_count = leaves.len();
        let height = (leaf_count as f64).log2().ceil() as usize;
        let first_leaf_pos = 1 << height;
        let mut nodes = BTreeMap::new();

        // Insert leaf nodes
        for (idx, &hash) in leaves.iter().enumerate() {
            let position = first_leaf_pos + idx;
            nodes.insert(position, Node { hash, position });
        }

        // For unbalanced trees, we don't duplicate leaves

        let mut tree = Self { nodes, leaf_count, height, first_leaf_pos };
        tree.build_internal_nodes();
        Ok(tree)
    }

    /// Returns the root hash of the tree
    pub fn root(&self) -> H256 {
        self.nodes.get(&1).map(|n| n.hash).unwrap_or_default()
    }

    /// Generates merkle proof for multiple leaf indices
    pub fn generate_multi_proof(&self, indices: &[usize]) -> Result<Vec<Vec<Node>>, MerkleError> {
        // Validate indices
        for &idx in indices {
            if idx >= self.leaf_count {
                return Err(MerkleError::InvalidIndex(idx));
            }
        }

        let mut proof_layers = vec![Vec::new(); self.height];
        let mut current_level_positions: HashSet<usize> =
            indices.iter().map(|&idx| self.first_leaf_pos + idx).collect();

        // Build proof bottom-up
        for level in (0..self.height).rev() {
            let mut next_level_positions = HashSet::new();
            let mut level_proof = Vec::new();

            // Process each position at this level
            for &pos in &current_level_positions {
                let parent_pos = pos / 2;
                next_level_positions.insert(parent_pos);

                // Find sibling
                let sibling_pos = if pos % 2 == 0 { pos + 1 } else { pos - 1 };

                // Add sibling to proof if it's not in our tracked positions
                if !current_level_positions.contains(&sibling_pos) {
                    if let Some(sibling) = self.nodes.get(&sibling_pos) {
                        level_proof.push(sibling.clone());
                    }
                }
            }

            // Sort proof nodes by position
            level_proof.sort_by_key(|node| node.position);
            if !level_proof.is_empty() {
                proof_layers[level] = level_proof;
            }

            current_level_positions = next_level_positions;
        }

        Ok(proof_layers)
    }

    /// Verifies a multi-leaf merkle proof
    pub fn verify_multi_proof(
        root: H256,
        leaf_indices: &[usize],
        leaf_values: &[H256],
        proof: &[Vec<Node>],
        tree_height: usize,
    ) -> Result<bool, MerkleError> {
        if leaf_indices.len() != leaf_values.len() {
            return Err(MerkleError::InvalidProof("mismatched leaves and indices"));
        }

        let first_leaf_pos = 1 << tree_height;

        // Start with the leaves we're proving
        let mut current_level: BTreeMap<usize, H256> = leaf_indices
            .iter()
            .zip(leaf_values)
            .map(|(&idx, &value)| (first_leaf_pos + idx, value))
            .collect();

        // Process each level bottom-up
        for (level, proof_nodes) in proof.iter().enumerate().rev() {
            let mut next_level = BTreeMap::new();
            let mut processed = HashSet::new();

            // Add proof nodes to current level
            for node in proof_nodes {
                current_level.insert(node.position, node.hash);
            }

            // Calculate parent nodes
            for &pos in current_level.keys() {
                let parent_pos = pos / 2;
                if processed.contains(&parent_pos) {
                    continue;
                }
                processed.insert(parent_pos);

                let left_pos = parent_pos * 2;
                let right_pos = left_pos + 1;

                match (current_level.get(&left_pos), current_level.get(&right_pos)) {
                    (Some(&left), Some(&right)) => {
                        let parent_hash = Self::hash_pair(left, right);
                        next_level.insert(parent_pos, parent_hash);
                    },
                    (Some(&single), None) => {
                        // For unbalanced trees, promote single nodes
                        next_level.insert(parent_pos, single);
                    },
                    (None, Some(&single)) => {
                        // For unbalanced trees, promote single nodes
                        next_level.insert(parent_pos, single);
                    },
                    _ => return Err(MerkleError::InvalidProof("invalid tree structure")),
                }
            }

            current_level = next_level;
        }

        // Verify we ended up with just the root
        Ok(current_level.len() == 1 && current_level.get(&1) == Some(&root))
    }

    /// Builds the internal nodes of the tree bottom-up
    fn build_internal_nodes(&mut self) {
        for level in (0..self.height).rev() {
            let start_pos = 1 << level;
            let end_pos = (1 << (level + 1)) - 1;

            for pos in start_pos..=end_pos {
                let left_pos = pos * 2;
                let right_pos = left_pos + 1;

                match (self.nodes.get(&left_pos), self.nodes.get(&right_pos)) {
                    (Some(left), Some(right)) => {
                        let hash = Self::hash_pair(left.hash, right.hash);
                        self.nodes.insert(pos, Node { hash, position: pos });
                    },
                    (Some(single), None) | (None, Some(single)) => {
                        // For unbalanced trees, promote single nodes
                        self.nodes.insert(pos, Node { hash: single.hash, position: pos });
                    },
                    _ => {}, // Skip empty branches
                }
            }
        }
    }

    /// Combines two hashes using keccak256
    fn hash_pair(left: H256, right: H256) -> H256 {
        H256(keccak256([left.as_bytes(), right.as_bytes()].concat()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_hash() -> H256 {
        H256::random()
    }

    #[test]
    fn test_unbalanced_tree() {
        // Create tree with 3 leaves (unbalanced)
        let leaves: Vec<H256> = (0..3).map(|_| random_hash()).collect();
        let tree = PositionalMerkleTree::new(&leaves).unwrap();

        // Generate and verify proof for last leaf (which has no sibling)
        let indices = vec![2];
        let proof = tree.generate_multi_proof(&indices).unwrap();
        let leaf_values = vec![leaves[2]];

        assert!(PositionalMerkleTree::verify_multi_proof(
            tree.root(),
            &indices,
            &leaf_values,
            &proof,
            tree.height
        )
        .unwrap());
    }

    #[test]
    fn test_unbalanced_tree_multiple_proofs() {
        // Create tree with 5 leaves (unbalanced)
        let leaves: Vec<H256> = (0..5).map(|_| random_hash()).collect();
        let tree = PositionalMerkleTree::new(&leaves).unwrap();

        // Generate and verify proof for indices including the last leaf
        let indices = vec![1, 3, 4];
        let proof = tree.generate_multi_proof(&indices).unwrap();
        let leaf_values: Vec<H256> = indices.iter().map(|&i| leaves[i]).collect();

        assert!(PositionalMerkleTree::verify_multi_proof(
            tree.root(),
            &indices,
            &leaf_values,
            &proof,
            tree.height
        )
        .unwrap());
    }

    #[test]
    fn test_empty_tree() {
        assert!(matches!(PositionalMerkleTree::new(&[]), Err(MerkleError::EmptyTree)));
    }

    #[test]
    fn test_single_leaf() {
        let leaf = random_hash();
        let tree = PositionalMerkleTree::new(&[leaf]).unwrap();
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_multi_proof() {
        let leaves: Vec<H256> = (0..8).map(|_| random_hash()).collect();
        let tree = PositionalMerkleTree::new(&leaves).unwrap();

        // Generate and verify proof for indices 1, 4, 6
        let indices = vec![1, 4, 6];
        let proof = tree.generate_multi_proof(&indices).unwrap();

        // Verify the proof
        let leaf_values: Vec<H256> = indices.iter().map(|&i| leaves[i]).collect();
        assert!(PositionalMerkleTree::verify_multi_proof(
            tree.root(),
            &indices,
            &leaf_values,
            &proof,
            tree.height
        )
        .unwrap());
    }

    #[test]
    fn test_sorted_proof_layers() {
        let leaves: Vec<H256> = (0..8).map(|_| random_hash()).collect();
        let tree = PositionalMerkleTree::new(&leaves).unwrap();

        let indices = vec![1, 4, 6];
        let proof = tree.generate_multi_proof(&indices).unwrap();

        // Verify each layer is sorted by position
        for layer in proof.iter() {
            let positions: Vec<usize> = layer.iter().map(|n| n.position).collect();
            let mut sorted = positions.clone();
            sorted.sort();
            assert_eq!(positions, sorted, "Proof layer not sorted by position");
        }
    }

    #[test]
    fn test_invalid_index() {
        let leaves: Vec<H256> = (0..4).map(|_| random_hash()).collect();
        let tree = PositionalMerkleTree::new(&leaves).unwrap();

        assert!(matches!(tree.generate_multi_proof(&[5]), Err(MerkleError::InvalidIndex(5))));
    }
}
