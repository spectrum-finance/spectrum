use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;

use crate::block::{BlockHeader, BlockSection, BlockSectionId};

/// Read-only async API to ledger history.
#[async_trait]
pub trait HistoryReadAsync: Send + Sync {
    async fn get_section(&self, id: BlockSectionId) -> Option<BlockSection>;
    /// Get chain tip header (best block header).
    async fn get_tip(&self) -> BlockHeader;
    async fn get_tail(&self, n: usize) -> Vec<BlockHeader>;
}

pub struct HistoryRocksDB {
    pub db: Arc<rocksdb::OptimisticTransactionDB>,
}

#[async_trait]
impl HistoryReadAsync for HistoryRocksDB {
    async fn get_section(&self, id: BlockSectionId) -> Option<BlockSection> {
        let db = self.db.clone();
        let key = bincode::serialize(&id).unwrap();
        spawn_blocking(move || db.get(key).unwrap().and_then(|bs| bincode::deserialize(&bs).ok())).await
    }

    async fn get_tip(&self) -> BlockHeader {
        todo!()
    }

    async fn get_tail(&self, n: usize) -> Vec<BlockHeader> {
        todo!()
    }
}
