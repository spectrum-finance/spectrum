use spectrum_ledger::block::BlockHeader;
use spectrum_ledger::SlotNo;

pub trait HeaderLike: Send + Sync {
    fn slot_num(&self) -> SlotNo;
}

impl HeaderLike for BlockHeader {
    fn slot_num(&self) -> SlotNo {
        self.body.slot_num
    }
}
