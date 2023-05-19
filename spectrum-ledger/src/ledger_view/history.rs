use futures::channel::oneshot::Receiver;

use crate::block::{BlockSection, BlockSectionId};

/// Async API to ledger history.
pub trait HistoryAsync {
    fn get_section(&mut self, id: BlockSectionId) -> Receiver<BlockSection>;
}
