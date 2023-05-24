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

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;

    use nonempty::NonEmpty;

    use crate::block::{BlockHeader, BlockId, BlockSection, BlockSectionId};
    use crate::ledger_view::history::HistoryReadAsync;

    pub struct EphemeralHistory {
        pub db: HashMap<BlockId, BlockSection>,
    }

    #[async_trait::async_trait]
    impl HistoryReadAsync for EphemeralHistory {
        async fn member(&self, id: &BlockId) -> bool {
            self.db.contains_key(id)
        }

        async fn get_section(&self, id: &BlockSectionId) -> Option<BlockSection> {
            match id {
                BlockSectionId::Header(id) | BlockSectionId::Payload(id) => self.db.get(id).cloned(),
            }
        }

        async fn get_tip(&self) -> BlockHeader {
            self.db
                .values()
                .filter_map(|s| match s {
                    BlockSection::Header(bh) => Some(bh),
                    _ => None,
                })
                .max_by_key(|hd| hd.slot)
                .cloned()
                .unwrap_or(BlockHeader::ORIGIN)
        }

        async fn get_tail(&self, n: usize) -> NonEmpty<BlockHeader> {
            let mut headers = self
                .db
                .values()
                .filter_map(|s| match s {
                    BlockSection::Header(bh) => Some(bh),
                    _ => None,
                })
                .collect::<Vec<_>>();
            headers.sort_by_key(|hd| hd.slot);
            NonEmpty::collect(headers[headers.len() - n..].into_iter().map(|&hd| hd.clone()))
                .unwrap_or(NonEmpty::singleton(BlockHeader::ORIGIN))
        }
    }
}
