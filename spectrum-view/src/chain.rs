use spectrum_ledger::block::{BlockHeader, BlockId};
use spectrum_ledger::SlotNo;

pub trait HeaderLike: Send + Sync {
    fn id(&self) -> BlockId;
    fn slot_num(&self) -> SlotNo;
}

impl HeaderLike for BlockHeader {
    fn id(&self) -> BlockId {
        self.id
    }
    fn slot_num(&self) -> SlotNo {
        self.body.slot_num
    }
}
