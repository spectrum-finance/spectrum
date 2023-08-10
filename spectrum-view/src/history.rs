use std::sync::Arc;

use async_trait::async_trait;
use nonempty::NonEmpty;

use spectrum_ledger::block::{
    BlockBody, BlockHeader, BlockId, BlockSectionType, RecoverableSection, ValidSection,
};
use spectrum_ledger::{ModifierId, ModifierRecord, SerializedModifier, SlotNo};

use crate::chain::HeaderLike;

/// Sync API to ledger history.
pub trait LedgerHistoryWrite {
    /// Apply block header.
    fn apply_header(&self, hdr: ValidSection<BlockHeader>);
    /// Save block header.
    fn save_header(&self, hdr: RecoverableSection<BlockHeader>);
    /// Apply block body.
    fn apply_body(&self, body: ValidSection<BlockBody>);
    /// Save block body.
    fn save_body(&self, body: RecoverableSection<BlockBody>);
}

pub trait LedgerHistoryReadSync {
    fn get_header(&self, id: &BlockId) -> Option<BlockHeader>;
    fn get_header_at(&self, slot: SlotNo) -> Option<BlockHeader>;
}

/// Read-only async API to ledger history.
#[async_trait]
pub trait LedgerHistoryReadAsync<H: HeaderLike>: Send + Sync {
    /// Check if the given block is in the best chain.
    async fn member(&self, id: &BlockId) -> bool;
    /// Check if the given modifier exists in history.
    async fn contains(&self, id: &ModifierId) -> bool;
    /// Get chain tip header (best block header).
    async fn get_tip(&self) -> ModifierRecord<H>;
    /// Get tail of the chain. Chain always has at least origin block.
    async fn get_tail(&self, n: usize) -> NonEmpty<ModifierRecord<H>>;
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
impl LedgerHistoryReadAsync<BlockHeader> for LedgerHistoryRocksDB {
    async fn member(&self, id: &BlockId) -> bool {
        todo!()
    }

    async fn contains(&self, id: &ModifierId) -> bool {
        todo!()
    }

    async fn get_tip(&self) -> ModifierRecord<BlockHeader> {
        todo!()
    }

    async fn get_tail(&self, n: usize) -> NonEmpty<ModifierRecord<BlockHeader>> {
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
