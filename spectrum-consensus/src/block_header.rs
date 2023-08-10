use spectrum_crypto::digest::Blake2b256;
use spectrum_ledger::block::BlockHeader;
use spectrum_view::history::LedgerHistoryReadSync;
use spectrum_view::state::ConsensusIndexes;
use spectrum_vrf::lottery::proof_to_random_number;

use crate::constants::EPOCH_MEMBERSHIP_SALT;
use crate::protocol_params::ProtocolParams;
use crate::rules::{
    ConsensusRuleSet, HEADER_EPOCH_SEED, HEADER_NON_DESC_SLOT, HEADER_PARENT_LINK, HEADER_PARENT_SLOT_DELTA,
};
use crate::validation::{AsInvalidModifier, Validation, ValidationState};

pub fn validate_block_header<H, S, RS, PP>(
    hdr: BlockHeader,
    history: &H,
    state: &S,
    rules: &RS,
    protocol: &PP,
) -> Validation<BlockHeader, (), ()>
where
    H: LedgerHistoryReadSync,
    S: ConsensusIndexes,
    RS: ConsensusRuleSet,
    PP: ProtocolParams,
{
    Validation::new(hdr).and_then(|hdr, _| {
        let prev_id = hdr.body.prev_id;
        if let Some(parent_hdr) = history.get_header(&prev_id) {
            validate_child_block_header(hdr, parent_hdr, history, state, rules, protocol)
        } else {
            ValidationState::fail(
                HEADER_PARENT_LINK,
                rules,
                hdr.as_invalid(format!("Parent header with ID {} not found", prev_id)),
            )
        }
    })
}

fn validate_child_block_header<H, S, RS, PP>(
    hdr: &BlockHeader,
    parent_hdr: BlockHeader,
    history: &H,
    state: &S,
    rules: &RS,
    protocol: &PP,
) -> ValidationState<(), ()>
where
    H: LedgerHistoryReadSync,
    S: ConsensusIndexes,
    RS: ConsensusRuleSet,
    PP: ProtocolParams,
{
    ValidationState::new(hdr)
        .asset_term(
            HEADER_NON_DESC_SLOT,
            rules,
            |hdr| hdr.body.slot_num > parent_hdr.body.slot_num,
            |hdr| {
                hdr.as_invalid(format!(
                    "Non increasing slot number, parent slot {}, header slot {}",
                    parent_hdr.body.slot_num, hdr.body.slot_num
                ))
            },
        )
        .flat_tap(|hdr| {
            let delta = hdr.body.slot_num - parent_hdr.body.slot_num;
            let allowed_delta = protocol.fk();
            if delta <= allowed_delta.into() {
                ValidationState::fail(
                    HEADER_PARENT_SLOT_DELTA,
                    rules,
                    hdr.as_invalid(format!(
                        "Slot delta out of bounds. Max allowed delta is {}, actual {}",
                        allowed_delta, delta
                    )),
                )
            } else {
                ValidationState::ok()
            }
        })
        .flat_tap(|hdr| {
            let epoch = hdr.body.slot_num.epoch_num();
            if let Some(epoch_rand_proof) = state.get_epoch_rand_proof(hdr.body.slot_num.epoch_num()) {
                let epoch_seed = proof_to_random_number::<Blake2b256, _>(
                    &epoch_rand_proof.into(),
                    EPOCH_MEMBERSHIP_SALT.as_bytes().to_vec(),
                    protocol.base_vrf_range(),
                );
                ValidationState::ok()
            } else {
                ValidationState::fail(
                    HEADER_EPOCH_SEED,
                    rules,
                    hdr.as_invalid(format!("Randomness proof for epoch {} not found", epoch)),
                )
            }
        })
        .discard()
}
