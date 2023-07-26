use std::sync::Arc;

use async_trait::async_trait;
use nonempty::NonEmpty;

use spectrum_ledger::block::{
    BlockBody, BlockHeader, BlockId, BlockSection, BlockSectionId, BlockSectionType,
};
use spectrum_ledger::{ModifierId, SerializedModifier};

use crate::chain::HeaderLike;
use crate::state::LedgerStateError;
use crate::validation::{CanValidate, RecoverableModifier, ValidModifier, ValidationResult};

#[derive(Eq, PartialEq, Debug)]
pub enum InvalidBlockSection {
    InvalidHeader(FatalHeaderError),
    InvalidBody(FatalBlockBodyError),
    InvalidBlock(LedgerStateError),
}

/// Sync API to ledger history.
pub trait LedgerHistory {
    /// Apply block header.
    fn apply_header(&self, hdr: &BlockHeader) -> Result<(), FatalHeaderError>;
    /// Apply block body.
    fn apply_body(&self, body: &BlockBody) -> Result<(), FatalBlockBodyError>;
}

pub trait LedgerHistoryReadSync {
    fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection>;
}

/// Read-only async API to ledger history.
#[async_trait]
pub trait LedgerHistoryReadAsync<H: HeaderLike>: Send + Sync {
    /// Check if the given block is in the best chain.
    async fn member(&self, id: &BlockId) -> bool;
    /// Check if the given modifier exists in history.
    async fn contains(&self, id: &ModifierId) -> bool;
    /// Get chain tip header (best block header).
    async fn get_tip(&self) -> H;
    /// Get tail of the chain. Chain always has at least origin block.
    async fn get_tail(&self, n: usize) -> NonEmpty<H>;
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

impl LedgerHistoryRocksDB {
    pub fn apply_header(&self, hdr: ValidModifier<&BlockHeader>) {}
    pub fn apply_recoverable_header(&self, hdr: RecoverableModifier<&BlockHeader>) {}
}

impl LedgerHistory for LedgerHistoryRocksDB {
    fn apply_header(&self, hdr: &BlockHeader) -> Result<(), FatalHeaderError> {
        match self.try_validate(hdr) {
            ValidationResult::Fatal(err) => Err(err),
            ValidationResult::NonFatal(recov, _) => Ok(self.apply_recoverable_header(recov)),
            ValidationResult::Valid(hdr) => Ok(self.apply_header(hdr)),
        }
    }

    fn apply_body(&self, section: &BlockBody) -> Result<(), FatalBlockBodyError> {
        todo!()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct FatalHeaderError {}

#[derive(Eq, PartialEq, Debug)]
pub struct RecovHeaderError {}

impl<T: LedgerHistoryReadSync> CanValidate<BlockHeader, FatalHeaderError, RecovHeaderError> for T {
    fn try_validate(
        &self,
        md: &BlockHeader,
    ) -> ValidationResult<&BlockHeader, FatalHeaderError, RecovHeaderError> {
        todo!()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct FatalBlockBodyError {}

#[derive(Eq, PartialEq, Debug)]
pub struct RecovBlockBodyError {}

impl<T: LedgerHistoryReadSync> CanValidate<BlockBody, FatalBlockBodyError, RecovBlockBodyError> for T {
    fn try_validate(
        &self,
        md: &BlockBody,
    ) -> ValidationResult<&BlockBody, FatalBlockBodyError, RecovBlockBodyError> {
        todo!()
    }
}

impl LedgerHistoryReadSync for LedgerHistoryRocksDB {
    fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection> {
        todo!()
    }
}

#[async_trait]
impl LedgerHistoryReadAsync<BlockHeader> for LedgerHistoryRocksDB {
    async fn member(&self, id: &BlockId) -> bool {
        todo!()
    }

    async fn contains(&self, id: &ModifierId) -> bool {
        todo!()
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
