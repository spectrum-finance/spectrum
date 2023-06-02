use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use nonempty::NonEmpty;

use spectrum_ledger::block::{BlockHeader, BlockId, BlockSection, BlockSectionId, BlockSectionType};
use spectrum_ledger::{ModifierId, SerializedModifier};

#[derive(Eq, PartialEq, Debug)]
pub struct InvalidBlockSection;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum LedgerHistoryError {
    #[error("Invalid block section")]
    InvalidBlockSection,
}

/// Sync API to ledger history.
pub trait LedgerHistory {
    /// Apply block section
    fn apply_section(&self, section: BlockSection) -> Result<(), InvalidBlockSection>;
}

/// Read-only async API to ledger history.
#[async_trait]
pub trait LedgerHistoryReadAsync: Send + Sync {
    /// Check if the given block is in the best chain.
    async fn member(&self, id: &BlockId) -> bool;
    /// Check if the given modifier exists in history.
    async fn contains(&self, id: &ModifierId) -> bool;
    async fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection>;
    /// Get chain tip header (best block header).
    async fn get_tip(&self) -> BlockHeader;
    /// Get tail of the chain. Chain always has at least origin block.
    async fn get_tail(&self, n: usize) -> NonEmpty<BlockHeader>;
    /// Follow best chain starting from `pre_start` until either the local tip
    /// is reached or `n` blocks are collected..
    async fn follow(&self, pre_start: BlockId, cap: usize) -> Vec<BlockId>;
    /// Bulk select block sections of the specified type.
    /// The modifiers are returned in serialized form.
    async fn multi_get_raw(
        &self,
        sec_type: BlockSectionType,
        ids: Vec<ModifierId>,
    ) -> Vec<SerializedModifier>;
}

pub struct LedgerHistoryRocksDB {
    pub db: Arc<rocksdb::OptimisticTransactionDB>,
}

#[async_trait]
impl LedgerHistoryReadAsync for LedgerHistoryRocksDB {
    async fn member(&self, id: &BlockId) -> bool {
        todo!()
    }

    async fn contains(&self, id: &ModifierId) -> bool {
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

    async fn follow(&self, pre_start: BlockId, n: usize) -> Vec<BlockId> {
        todo!()
    }

    async fn multi_get_raw(
        &self,
        sec_type: BlockSectionType,
        ids: Vec<ModifierId>,
    ) -> Vec<SerializedModifier> {
        todo!()
    }
}
