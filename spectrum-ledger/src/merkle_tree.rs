use std::collections::VecDeque;

use spectrum_crypto::digest::blake2b256_hash;

pub struct SparseMerkleProofBuilder {
    /// A listing of leaf data, ordered from left to right.
    pub leaves: Vec<Vec<u8>>,
    /// The hashes of every node in the Merkle tree. Ordered from left to right, by level. E.g. the
    /// following tree
    /// ```text
    ///         6
    ///     4       5
    ///   0   1   2   3
    /// ```
    /// is arranged as `[0, 1, 2, 3, 4, 5, 6]`. Note that the hashes are all prefixed with 0 if
    /// they are leaf nodes and 1 if they are non-leaf.
    pub hashes: Vec<Vec<u8>>,
    pub num_leaves: usize,
    pub root_hash: Vec<u8>,
    indexer: MerkleTreeIndexer,
}

/// All leaf nodes of the Merkle tree are prefixed with 0_u8, to prevent second-preimage attack.
const LEAF_PREFIX: u8 = 0;
/// All internal (non-leaf) nodes of the Merkle tree are prefixed with 1_u8, to prevent
/// second-preimage attack.
const INTERNAL_PREFIX: u8 = 1;

#[derive(Debug)]
pub enum Error {
    NumberOfLeavesNotPowerOf2,
    NonLeafIndexSelected(usize),
}

impl SparseMerkleProofBuilder {
    pub fn new(leaves: Vec<Vec<u8>>) -> Result<Self, Error> {
        let num_leaves = leaves.len();
        let indexer = MerkleTreeIndexer::new(num_leaves)?;
        let mut hashes_by_level = vec![];

        let mut current_level = Vec::with_capacity(num_leaves);

        // Create leaf nodes in level 0
        for leaf_bytes in &leaves {
            let mut data = vec![LEAF_PREFIX];
            data.extend(Vec::from(blake2b256_hash(leaf_bytes)));
            current_level.push(data);
        }

        hashes_by_level.push(current_level);

        for _ in 1..indexer.first_ix_of_levels.len() {
            {
                let current_level = hashes_by_level.last().unwrap();
                let mut next_level = Vec::with_capacity(current_level.len() / 2);
                for (left, right) in current_level.iter().zip(current_level.iter().skip(1)).step_by(2) {
                    next_level.push(compute_internal_node(left, right));
                }
                hashes_by_level.push(next_level);
            }
        }

        let hashes = hashes_by_level.into_iter().flatten().collect::<Vec<Vec<u8>>>();
        let root_hash = hashes.last().unwrap().clone();

        Ok(Self {
            leaves,
            hashes,
            num_leaves,
            root_hash,
            indexer,
        })
    }

    pub fn build_packed_proof(
        &self,
        ix_last_node_to_verify: usize,
    ) -> Result<PackedSparseMerkleProof, Error> {
        if ix_last_node_to_verify >= self.num_leaves {
            return Err(Error::NonLeafIndexSelected(ix_last_node_to_verify));
        }
        let mut needed_internal_nodes = vec![];

        let (mut current_ix, right_peer_hash) = if is_left(ix_last_node_to_verify) {
            // Take HLOA for right-peer.
            let hloa = self
                .indexer
                .highest_left_only_ancestor(ix_last_node_to_verify + 1)
                .unwrap();
            (hloa, Some(ix_last_node_to_verify + 1))
        } else {
            // HLOA always exists for a right-child.
            let hloa = self
                .indexer
                .highest_left_only_ancestor(ix_last_node_to_verify)
                .unwrap();
            (hloa, None)
        };

        loop {
            if let Some(hloa) = self.indexer.highest_left_only_ancestor(current_ix) {
                if !self.indexer.is_root_ix(hloa) {
                    let level = self.indexer.get_level(hloa).unwrap();
                    current_ix = hloa + 1;
                    needed_internal_nodes.push((level, self.hashes[current_ix].clone()));
                } else {
                    break;
                }
            } else if !self.indexer.is_root_ix(current_ix) {
                let level = self.indexer.get_level(current_ix).unwrap();
                current_ix += 1;
                needed_internal_nodes.push((level, self.hashes[current_ix].clone()));
            } else {
                break;
            }
        }

        let leaf_nodes_to_verify = self.leaves.clone();
        Ok(PackedSparseMerkleProof {
            leaf_nodes_to_verify,
            needed_internal_nodes,
            right_peer_hash,
            root_hash: self.root_hash.clone(),
        })
    }
}

#[derive(Debug)]
pub struct PackedSparseMerkleProof {
    /// This Vec is contiguous. E.g. if it contains 4 nodes, then they represents nodes 0, 1, 2 and
    /// 3 in the Merkle tree (ordered left to right).
    pub leaf_nodes_to_verify: Vec<Vec<u8>>,
    /// Internal nodes that are necessary to complete the Merkle multi proof, together with their
    /// level in the Merkle tree.
    pub needed_internal_nodes: Vec<(usize, Vec<u8>)>,
    /// If the last leaf in `leaf_nodes_to_verify` is a left-child, then the Merkle proof requires
    /// the hashed value of the right peer leaf.
    pub right_peer_hash: Option<usize>,
    /// The root hash value of the Merkle tree.
    pub root_hash: Vec<u8>,
}

impl PackedSparseMerkleProof {
    pub fn verify(&self, hashes: &[Vec<u8>], highest_level: usize) -> bool {
        let mut current_level = 0;
        let mut hashes_in_current_level: Vec<_> = self
            .leaf_nodes_to_verify
            .iter()
            .map(|leaf_bytes| {
                let mut data = vec![LEAF_PREFIX];
                data.extend(Vec::from(blake2b256_hash(leaf_bytes)));
                data
            })
            .collect();
        if let Some(right_peer_ix) = &self.right_peer_hash {
            hashes_in_current_level.push(hashes[*right_peer_ix].clone());
        }
        let mut hashes_in_next_level = Vec::with_capacity(hashes_in_current_level.len() / 2);

        while current_level < highest_level {
            for (left, right) in hashes_in_current_level
                .iter()
                .zip(hashes_in_current_level.iter().skip(1))
                .step_by(2)
            {
                hashes_in_next_level.push(compute_internal_node(left, right));
            }

            hashes_in_current_level.clear();
            hashes_in_current_level.extend_from_slice(&hashes_in_next_level);
            for internal_node_hash in self.needed_internal_nodes.iter().filter_map(|(level, hash)| {
                if *level == current_level + 1 {
                    Some(hash)
                } else {
                    None
                }
            }) {
                hashes_in_current_level.push(internal_node_hash.clone());
            }
            current_level += 1;
            hashes_in_next_level.clear();
        }

        assert_eq!(hashes_in_current_level.len(), 1);

        hashes_in_current_level[0] == self.root_hash
    }
}

struct MerkleTreeIndexer {
    first_ix_of_levels: Vec<usize>,
    num_leaves: usize,
}

impl MerkleTreeIndexer {
    fn new(num_leaves: usize) -> Result<Self, Error> {
        if is_power_of_2(num_leaves) {
            let mut first_ix_of_levels = vec![0];
            let mut count = 0;
            let mut num_nodes_in_level = num_leaves;
            while num_nodes_in_level > 1 {
                count += num_nodes_in_level;
                first_ix_of_levels.push(count);
                num_nodes_in_level /= 2;
            }

            Ok(Self {
                first_ix_of_levels,
                num_leaves,
            })
        } else {
            Err(Error::NumberOfLeavesNotPowerOf2)
        }
    }

    fn get_level(&self, node_index: usize) -> Option<usize> {
        let last_ix = *self.first_ix_of_levels.last().unwrap();
        if node_index > last_ix {
            return None;
        }
        if node_index == last_ix {
            return Some(self.first_ix_of_levels.len() - 1);
        }
        self.first_ix_of_levels.windows(2).enumerate().find_map(|(i, w)| {
            if w[0] <= node_index && node_index < w[1] {
                Some(i)
            } else {
                None
            }
        })
    }

    fn parent(&self, ix: usize) -> Option<usize> {
        let level = self.get_level(ix)?;
        let next_level = *self.first_ix_of_levels.get(level + 1)?;
        let ix = self.position_in_level(ix)?;
        Some(ix / 2 + next_level)
    }

    fn position_in_level(&self, ix: usize) -> Option<usize> {
        self.get_level(ix)
            .map(|level| ix - self.first_ix_of_levels[level])
    }

    /// Returns the highest ancestor of `ix` that is only reachable through right-side children
    /// nodes. Let this function be denoted by HLOA.
    ///
    /// Example: given the following sub-tree with leaf nodes 0, 1, 2 and 3:
    /// ```text
    ///             ...
    ///            /
    ///           /
    ///          23
    ///        /    \
    ///       /      \
    ///     16        17   ...
    ///    /  \      /  \
    ///   0    1    2    3 ...
    /// ```
    /// Then
    /// ```text
    ///     HLOA(0) == HLOA(2) == None
    ///     HLOA(1) == Some(16)
    ///     HLOA(3) == HLOA(17) == Some(23)
    /// ```
    ///
    /// Given knowledge of all leaf nodes in the above tree, the HLOA represents the highest Merkle
    /// tree node that is computable from only the leaves.
    fn highest_left_only_ancestor(&self, ix: usize) -> Option<usize> {
        if is_left(ix) {
            return None;
        }
        let mut result = None;
        let mut current_ix = ix;

        while let Some(parent_ix) = self.parent(current_ix) {
            if is_left(parent_ix) {
                result = Some(parent_ix);
                break;
            } else {
                current_ix = parent_ix;
            }
        }
        result
    }

    fn num_tree_nodes(&self) -> usize {
        2 * self.num_leaves - 1
    }

    fn highest_level(&self) -> usize {
        self.first_ix_of_levels.len() - 1
    }

    fn is_root_ix(&self, ix: usize) -> bool {
        *self.first_ix_of_levels.last().unwrap() == ix
    }
}

fn compute_internal_node(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut data = vec![INTERNAL_PREFIX];
    let mut data_to_hash = Vec::with_capacity(2 * left.len());
    data_to_hash.extend_from_slice(left);
    data_to_hash.extend_from_slice(right);
    let hashed_bytes = Vec::from(blake2b256_hash(&data_to_hash));
    data.extend(hashed_bytes);
    data
}

// From: https://stackoverflow.com/a/600306
fn is_power_of_2(x: usize) -> bool {
    (x != 0) && ((x & (x - 1)) == 0)
}

fn is_left(ix: usize) -> bool {
    ix % 2 == 0
}

#[cfg(test)]
mod test {
    use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};

    use super::{MerkleTreeIndexer, SparseMerkleProofBuilder};

    #[test]
    fn merkle_tree_indexing() {
        let m = MerkleTreeIndexer::new(16).unwrap();
        assert_eq!(m.num_tree_nodes(), 31);
        println!("{:?}", m.first_ix_of_levels);

        // Test levels
        assert_eq!(m.get_level(0), Some(0));
        assert_eq!(m.get_level(15), Some(0));
        assert_eq!(m.get_level(16), Some(1));
        assert_eq!(m.get_level(23), Some(1));
        assert_eq!(m.get_level(24), Some(2));
        assert_eq!(m.get_level(27), Some(2));
        assert_eq!(m.get_level(28), Some(3));
        assert_eq!(m.get_level(29), Some(3));
        assert_eq!(m.get_level(30), Some(4));
        assert_eq!(m.get_level(31), None);

        // Test parents
        // Level 0
        assert_eq!(m.parent(0), Some(16));
        assert_eq!(m.parent(1), Some(16));
        assert_eq!(m.parent(2), Some(17));
        assert_eq!(m.parent(3), Some(17));
        assert_eq!(m.parent(4), Some(18));
        assert_eq!(m.parent(5), Some(18));
        assert_eq!(m.parent(6), Some(19));
        assert_eq!(m.parent(7), Some(19));
        assert_eq!(m.parent(8), Some(20));
        assert_eq!(m.parent(10), Some(21));
        assert_eq!(m.parent(11), Some(21));
        assert_eq!(m.parent(12), Some(22));
        assert_eq!(m.parent(13), Some(22));
        assert_eq!(m.parent(14), Some(23));
        assert_eq!(m.parent(15), Some(23));

        // Level 1
        assert_eq!(m.parent(16), Some(24));
        assert_eq!(m.parent(17), Some(24));
        assert_eq!(m.parent(18), Some(25));
        assert_eq!(m.parent(19), Some(25));
        assert_eq!(m.parent(20), Some(26));
        assert_eq!(m.parent(21), Some(26));
        assert_eq!(m.parent(22), Some(27));
        assert_eq!(m.parent(23), Some(27));

        // Level 2
        assert_eq!(m.parent(24), Some(28));
        assert_eq!(m.parent(25), Some(28));
        assert_eq!(m.parent(26), Some(29));
        assert_eq!(m.parent(27), Some(29));

        // Level 3
        assert_eq!(m.parent(28), Some(30));
        assert_eq!(m.parent(29), Some(30));
    }

    #[test]
    fn test_merkle_leftmost_ancestor() {
        let m = MerkleTreeIndexer::new(16).unwrap();

        for i in (0..15).step_by(2) {
            assert_eq!(m.highest_left_only_ancestor(i), None);
        }
        assert_eq!(m.highest_left_only_ancestor(1), Some(16));
        assert_eq!(m.highest_left_only_ancestor(3), Some(24));
        assert_eq!(m.highest_left_only_ancestor(5), Some(18));
        assert_eq!(m.highest_left_only_ancestor(7), Some(28));
        assert_eq!(m.highest_left_only_ancestor(9), Some(20));
        assert_eq!(m.highest_left_only_ancestor(11), Some(26));
        assert_eq!(m.highest_left_only_ancestor(13), Some(22));
        assert_eq!(m.highest_left_only_ancestor(15), Some(30));
    }

    #[test]
    fn verify_merkle_root() {
        let num_leaves = 16;
        let prefixed_leaves = (0..num_leaves)
            .map(|_| Vec::from(Blake2bDigest256::random()))
            .collect::<Vec<Vec<u8>>>();

        let tree = SparseMerkleProofBuilder::new(prefixed_leaves).unwrap();
        assert_eq!(tree.hashes.len(), 31);
    }

    #[test]
    fn packed_merkle_proof() {
        let num_leaves = 256;
        let prefixed_leaves = (0..num_leaves)
            .map(|i: usize| i.to_be_bytes().to_vec())
            .collect::<Vec<Vec<u8>>>();

        let tree = SparseMerkleProofBuilder::new(prefixed_leaves).unwrap();
        for i in 0..num_leaves {
            let packed = tree.build_packed_proof(i).unwrap();
            println!("i: {}, needed: {:?}", i, packed.needed_internal_nodes);
            assert!(packed.verify(&tree.hashes, tree.indexer.highest_level()));
        }
    }

    #[test]
    fn gen_aiken_test() {
        let num_leaves: usize = 256;
        let verify_up_to = 199;
        let mut leaves = vec![];
        println!("test verify_{}_of_{}() {{", verify_up_to, num_leaves);
        for i in 0..num_leaves {
            let leaf_data = Vec::from(blake2b256_hash(format!("a{}", i).as_bytes()));
            if i <= verify_up_to {
                println!("  let tx_{} = #{:?}", i, leaf_data);
            }
            leaves.push(leaf_data);
        }
        //for i in 0..num_leaves {
        //    println!("  let n_{} = bytearray.push(blake2b_256(tx_{}), 0)", i, i);
        //}

        let tree = SparseMerkleProofBuilder::new(leaves).unwrap();
        //let num_nodes = tree.indexer.num_tree_nodes();
        //for (left, right) in (0..num_nodes).zip((0..num_nodes).skip(1)).step_by(2) {
        //    let parent = tree.indexer.parent(left).unwrap();
        //    println!(
        //        "  let n_{} = bytearray.push(bytearray.concat(n_{}, n_{}) |> blake2b_256, 1)",
        //        parent, left, right
        //    );
        //}

        let proof = tree.build_packed_proof(verify_up_to).unwrap();
        println!("  let root = #{:?}", tree.hashes.last().unwrap());

        println!("  sparse_merkle_proof(");
        print!("[");
        for i in 0..=verify_up_to {
            print!("tx_{}, ", i);
        }
        print!("],");

        // internal nodes
        print!("[");
        for (level, hash) in proof.needed_internal_nodes {
            print!("({}, #{:?}),", level, hash);
        }
        print!("],");

        // right peer hash
        if let Some(right_peer_ix) = proof.right_peer_hash {
            println!("Some(#{:?}),", tree.hashes[right_peer_ix]);
        } else {
            println!("None,");
        }

        println!("root,)}}");
    }
}
