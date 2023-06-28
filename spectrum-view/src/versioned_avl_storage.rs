mod versioned_storage;

use std::{cell::RefCell, rc::Rc, vec};

use bytes::Bytes;
use ergo_chain_types::{ADDigest, DigestNError};
use scorex_crypto_avltree::{
    authenticated_tree_ops::AuthenticatedTreeOps,
    batch_avl_prover::BatchAVLProver,
    batch_node::{AVLTree, Node, NodeHeader, NodeId},
};

use versioned_storage::{VersionId, VersionedStore};

type TreeHeight = usize;
type VersionedStoreType =
    VersionedStore<scorex_crypto_avltree::operation::Digest32, Vec<u8>, ADDigest, DigestNError>;

pub struct VersionedAVLStorage {
    store: VersionedStoreType,
    /// Necessary to have this here to (de)serialise AVL tree nodes.
    tree: AVLTree,
}

impl VersionedAVLStorage {
    pub async fn new(db_path: &str, num_versions_to_store: usize, tree: AVLTree) -> Self {
        let store = VersionedStore::new(db_path, num_versions_to_store).await;
        Self { store, tree }
    }

    pub async fn update(&mut self, prover: &mut BatchAVLProver) {
        let digest_bytes = prover.digest().unwrap().to_vec();
        let digest = ADDigest::try_from(digest_bytes).unwrap();
        let top_node = prover.top_node();
        let to_insert = serialize_visited_nodes(top_node, &self.tree);
        let to_remove: Vec<_> = prover
            .removed_nodes()
            .into_iter()
            .map(|node| {
                let mut node_cloned: Node = node.borrow().clone();
                node_cloned.label()
            })
            .collect();

        self.store.update(VersionId(digest), to_remove, to_insert).await;
    }

    pub async fn rollback_to(&mut self, version_id: VersionId<ADDigest>, prover: &mut BatchAVLProver) {
        self.store.rollback_to(version_id.clone()).await;
        let (root_node_label, height) = unpack_ad_digest(version_id.0);
        let (_, root) = &self.get(vec![root_node_label]).await[0];
        prover.base.tree.height = height;
        prover.base.tree.root = Some(root.clone().unwrap());
    }

    pub async fn get(
        &self,
        keys: Vec<scorex_crypto_avltree::operation::Digest32>,
    ) -> Vec<(scorex_crypto_avltree::operation::Digest32, Option<NodeId>)> {
        let mut res = vec![];

        for (key, vec_bytes) in self.store.get(keys).await {
            if let Some(vec_bytes) = vec_bytes {
                let bytes = Bytes::from(vec_bytes);
                let node = self.tree.unpack(&bytes);
                load_all_nodes(node.clone(), &self.store, &self.tree).await;
                res.push((key, Some(node)));
            } else {
                res.push((key, None));
            }
        }

        res
    }
}

/// Strictly load all descendent nodes of the AVL tree under `node` from versioned storage.
async fn load_all_nodes(node: NodeId, store: &VersionedStoreType, tree: &AVLTree) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if let Node::Internal(internal) = &mut *n.borrow_mut() {
            let left_node = if let Node::LabelOnly(NodeHeader { label, .. }) = &*internal.left.borrow() {
                let (_, b) = &store.get(vec![label.unwrap()]).await[0];
                let bytes = Bytes::from(b.clone().unwrap());
                let left_node = tree.unpack(&bytes);
                Some(left_node)
            } else {
                None
            };

            let right_node = if let Node::LabelOnly(NodeHeader { label, .. }) = &*internal.right.borrow() {
                let (_, b) = &store.get(vec![label.unwrap()]).await[0];
                let bytes = Bytes::from(b.clone().unwrap());
                let right_node = tree.unpack(&bytes);
                Some(right_node)
            } else {
                None
            };

            if let Some(left_node) = left_node {
                internal.left = left_node;
            }
            if let Some(right_node) = right_node {
                internal.right = right_node;
            }
            stack.push(internal.left.clone());
            stack.push(internal.right.clone());
        }
    }
}

fn serialize_visited_nodes(
    node: Rc<RefCell<Node>>,
    tree: &AVLTree,
) -> Vec<(scorex_crypto_avltree::operation::Digest32, Vec<u8>)> {
    let mut stack = vec![(node, true)];
    let mut result = vec![];

    while let Some((node, is_top)) = stack.pop() {
        let node_borrowed = node.borrow();
        let mut node_cloned: Node = node.borrow().clone();
        match *node_borrowed {
            Node::Internal(ref internal) => {
                if is_top || internal.hdr.is_new {
                    let node_bytes = tree.pack(node.clone()).to_vec();
                    let label = node_cloned.label();
                    result.push((label, node_bytes));
                    stack.push((internal.left.clone(), false));
                    stack.push((internal.right.clone(), false));
                }
            }
            Node::Leaf(ref leaf) => {
                if is_top || leaf.hdr.is_new {
                    let node_bytes = tree.pack(node.clone()).to_vec();
                    let label = node_cloned.label();
                    result.push((label, node_bytes));
                }
            }
            Node::LabelOnly(_) => {
                unreachable!();
            }
        }
    }
    result
}

fn unpack_ad_digest(ad_digest: ADDigest) -> (scorex_crypto_avltree::operation::Digest32, TreeHeight) {
    (
        <[u8; 32]>::try_from(&ad_digest.0[0..32]).unwrap(),
        ad_digest.0[32] as usize,
    )
}

#[cfg(test)]
mod tests {

    use bytes::Bytes;
    use rand::RngCore;
    use scorex_crypto_avltree::{
        authenticated_tree_ops::AuthenticatedTreeOps,
        batch_avl_prover::BatchAVLProver,
        batch_avl_verifier::BatchAVLVerifier,
        batch_node::{AVLTree, Node, NodeHeader, SerializedAdProof},
        operation::{ADKey, ADValue, Digest32, KeyValue, Operation},
    };

    use crate::versioned_avl_storage::versioned_storage::VersionId;

    use super::VersionedAVLStorage;

    const KEY_LENGTH: usize = 32;
    const VALUE_LENGTH: usize = 8;
    const TEST_ITERATIONS: usize = 10;
    pub const MIN_KEY: [u8; KEY_LENGTH] = [0u8; KEY_LENGTH];
    pub const MAX_KEY: [u8; KEY_LENGTH] = [0xFFu8; KEY_LENGTH];

    #[tokio::test]
    async fn test_rollback_after_1_operation() {
        let rnd = rand::thread_rng().next_u32();

        let tree = generate_tree(KEY_LENGTH, Some(VALUE_LENGTH));
        let mut store = VersionedAVLStorage::new(&format!("./tmp/{}", rnd), 10, tree).await;
        let mut prover = generate_prover(KEY_LENGTH, Some(VALUE_LENGTH));

        // Note: do not commit to storage a prover that has performed no operations. Rollback will
        // fail.
        let kv = random_kv();
        let m = Operation::Insert(kv);
        assert!(prover.perform_one_operation(&m).is_ok());
        let mut digest = prover.digest().unwrap();
        store.update(&mut prover).await;
        let _ = prover.generate_proof();

        for _ in 0..TEST_ITERATIONS {
            let kv = random_kv();
            let m = Operation::Insert(kv);
            assert!(prover.perform_one_operation(&m).is_ok());
            store.update(&mut prover).await;
            let _ = prover.generate_proof();

            // Rollback
            let d = ergo_chain_types::ADDigest::try_from(digest.clone().to_vec()).unwrap();
            store.rollback_to(VersionId(d), &mut prover).await;
            assert_eq!(prover.digest().unwrap(), digest);
            prover.check_tree(false);

            // Re-apply the operation
            assert!(prover.perform_one_operation(&m).is_ok());
            store.update(&mut prover).await;
            let _ = prover.generate_proof();
            digest = prover.digest().unwrap();
            prover.check_tree(false);
        }
    }

    #[tokio::test]
    async fn test_rollback_every_version() {
        let rnd = rand::thread_rng().next_u32();

        let tree = generate_tree(KEY_LENGTH, Some(VALUE_LENGTH));
        let num_versions = 50;
        let mut store = VersionedAVLStorage::new(&format!("./tmp/{}", rnd), num_versions, tree).await;
        let mut prover = generate_prover(KEY_LENGTH, Some(VALUE_LENGTH));

        let mut versions = vec![];
        for _ in 0..num_versions {
            for _ in 0..10 {
                let kv = random_kv();
                let m = Operation::Insert(kv);
                assert!(prover.perform_one_operation(&m).is_ok());
            }
            let digest_bytes = prover.digest().unwrap().to_vec();
            let digest = ergo_chain_types::ADDigest::try_from(digest_bytes).unwrap();
            versions.push(VersionId(digest));
            store.update(&mut prover).await;
            let _ = prover.generate_proof();
        }

        // Prover is already at the last version, so no point rolling back to it.
        let _ = versions.pop();

        versions.reverse();

        for v in versions {
            store.rollback_to(v.clone(), &mut prover).await;
            let d = prover.digest().unwrap().to_vec();
            assert_eq!(d, Vec::<u8>::from(v.0));
        }
    }

    fn random_key() -> ADKey {
        Bytes::copy_from_slice(&rand::random::<[u8; KEY_LENGTH]>())
    }

    fn random_value() -> ADValue {
        Bytes::copy_from_slice(&rand::random::<[u8; VALUE_LENGTH]>())
    }

    fn random_kv() -> KeyValue {
        loop {
            let key = random_key();
            if key != Bytes::copy_from_slice(&MIN_KEY) && key != Bytes::copy_from_slice(&MAX_KEY) {
                let value = random_value();
                return KeyValue { key, value };
            }
        }
    }

    fn generate_verifier(
        initial_digest: &scorex_crypto_avltree::operation::ADDigest,
        proof: &SerializedAdProof,
        key_length: usize,
        value_length: Option<usize>,
        max_num_operations: Option<usize>,
        max_deletes: Option<usize>,
    ) -> BatchAVLVerifier {
        BatchAVLVerifier::new(
            initial_digest,
            proof,
            generate_tree(key_length, value_length),
            max_num_operations,
            max_deletes,
        )
        .unwrap()
    }

    pub fn generate_tree(key_length: usize, value_length: Option<usize>) -> AVLTree {
        AVLTree::new(dummy_resolver, key_length, value_length)
    }

    pub fn generate_prover(key_length: usize, value_length: Option<usize>) -> BatchAVLProver {
        BatchAVLProver::new(generate_tree(key_length, value_length), true)
    }

    fn dummy_resolver(digest: &Digest32) -> Node {
        Node::LabelOnly(NodeHeader::new(Some(digest.clone()), None))
    }
}
