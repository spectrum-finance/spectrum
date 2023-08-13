use spectrum_crypto::digest::Blake2b256;
use spectrum_ledger::block::BlockHeader;
use spectrum_view::history::LedgerHistoryReadSync;
use spectrum_view::state::{ConsensusIndexes, StakeDistribution, ValidatorCredentials};
use spectrum_vrf::lottery::{lottery_threshold, proof_to_random_number};

use crate::constants::EPOCH_MEMBERSHIP_SALT;
use crate::protocol_params::ProtocolParams;
use crate::rules::{
    ConsensusRuleSet, HEADER_EPOCH_SEED, HEADER_NON_DESC_SLOT, HEADER_PARENT_LINK, HEADER_PARENT_SLOT_DELTA,
    HEADER_VALIDATOR_CREDS, HEADER_VALIDATOR_MEMBER,
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
    S: ConsensusIndexes + StakeDistribution + ValidatorCredentials,
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
    S: ConsensusIndexes + StakeDistribution + ValidatorCredentials,
    RS: ConsensusRuleSet,
    PP: ProtocolParams,
{
    ValidationState::new(hdr)
        .assert(
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
            ValidationState::assert_static(
                HEADER_PARENT_SLOT_DELTA,
                rules,
                || delta <= allowed_delta.into(),
                || {
                    hdr.as_invalid(format!(
                        "Slot delta out of bounds. Max allowed delta is {}, actual {}",
                        allowed_delta, delta
                    ))
                },
            )
        })
        .and_then(|hdr| {
            ValidationState::unwrap(
                HEADER_VALIDATOR_CREDS,
                rules,
                || state.get_pool_creds(hdr.body.vrf_vk.into()),
                || hdr.as_invalid(format!("Author not registered.")),
            )
            .map(|creds| (hdr, creds))
        })
        .flat_tap(|(hdr, creds)| {
            ValidationState::unwrap(
                HEADER_EPOCH_SEED,
                rules,
                || state.get_epoch_rand_proof(hdr.body.slot_num.epoch_num()),
                || {
                    hdr.as_invalid(format!(
                        "Randomness proof for epoch {} not found",
                        hdr.body.slot_num.epoch_num()
                    ))
                },
            )
            .and_then(|epoch_rand_proof| {
                let vrf_range = protocol.base_vrf_range();
                let consensus_selection_frac = protocol.consensus_selection_frac();
                let spo_stake = state.get_stake(hdr.body.vrf_vk.into());
                let total_stake = state.get_total_stake();
                let epoch_threshold = lottery_threshold(
                    vrf_range,
                    spo_stake.into(),
                    total_stake.into(),
                    consensus_selection_frac,
                );
                let epoch_seed = proof_to_random_number::<Blake2b256, _>(
                    &epoch_rand_proof.into(),
                    EPOCH_MEMBERSHIP_SALT.as_bytes().to_vec(),
                    vrf_range,
                );
                ValidationState::assert_static(
                    HEADER_VALIDATOR_MEMBER,
                    rules,
                    || epoch_seed < epoch_threshold,
                    || hdr.as_invalid(format!("Author not a member")),
                )
            })
        })
        .discard()
}
