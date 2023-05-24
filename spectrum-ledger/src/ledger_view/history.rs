use std::collections::HashMap;
use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use nonempty::NonEmpty;

use crate::block::{BlockHeader, BlockId, BlockSection, BlockSectionId};

/// Read-only async API to ledger history.
#[async_trait]
pub trait HistoryReadAsync: Send + Sync {
    /// Check if the given block is in the best chain.
    async fn member(&self, id: &BlockId) -> bool;
    async fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection>;
    /// Get chain tip header (best block header).
    async fn get_tip(&self) -> BlockHeader;
    /// Get tail of the chain. Chain always has at least origin block.
    async fn get_tail(&self, n: usize) -> NonEmpty<BlockHeader>;
}

pub struct HistoryRocksDB {
    pub db: Arc<rocksdb::OptimisticTransactionDB>,
}

#[async_trait]
impl HistoryReadAsync for HistoryRocksDB {
    async fn member(&self, id: &BlockId) -> bool {
        todo!()
    }

    async fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection> {
        let db = self.db.clone();
        let key = bincode::serialize(id).unwrap();
        spawn_blocking(move || db.get(key).unwrap().and_then(|bs| bincode::deserialize(&bs).ok())).await
    }

    async fn get_tip(&self) -> BlockHeader {
        todo!()
    }

    async fn get_tail(&self, n: usize) -> NonEmpty<BlockHeader> {
        todo!()
    }
}
