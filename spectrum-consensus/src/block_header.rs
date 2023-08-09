use spectrum_ledger::block::BlockHeader;
use spectrum_view::history::LedgerHistoryReadSync;

use crate::rules::{ConsensusRuleSet, HEADER_PARENT_LINK};
use crate::validation::{AsInvalidModifier, ValidationState};

pub fn validate_block_header<H, S, RS>(
    hdr: BlockHeader,
    history: &H,
    state: &S,
    rules: &RS,
) -> ValidationState<BlockHeader, ()>
where
    H: LedgerHistoryReadSync,
    RS: ConsensusRuleSet,
{
    let prev_id = hdr.body.prev_id;
    if let Some(parent_hdr) = history.get_header(&prev_id) {
        validate_child_block_header(hdr, parent_hdr, history, state, rules)
    } else {
        ValidationState::fail(
            HEADER_PARENT_LINK,
            rules,
            hdr.as_invalid(format!("Parent header with ID {} not found", prev_id)),
        )
    }
}

fn validate_child_block_header<H, S, RS>(
    hdr: BlockHeader,
    parent_hdr: BlockHeader,
    history: &H,
    state: &S,
    rules: &RS,
) -> ValidationState<BlockHeader, ()>
    where
        H: LedgerHistoryReadSync,
        RS: ConsensusRuleSet, {
    todo!()
}
