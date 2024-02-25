use ergo_lib::ergotree_ir::chain::{
    ergo_box::{box_value::BoxValue, ErgoBox},
    token::{Token, TokenId},
};
use serde::{Deserialize, Serialize};
use sigma_test_util::force_any_val;
use spectrum_ledger::cell::SValue;
use spectrum_offchain::event_sink::handlers::types::TryFromBoxCtx;

use crate::script::{ErgoCell, VAULT_CONTRACT};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct VaultUtxo {
    pub value: BoxValue,
    pub tokens: Vec<Token>,
}

impl TryFromBoxCtx<TokenId> for VaultUtxo {
    fn try_from_box(bx: ErgoBox, token_id: TokenId) -> Option<Self> {
        let is_vault_utxo = bx.ergo_tree == *VAULT_CONTRACT
            && bx.tokens.is_some()
            && bx.tokens.as_ref().unwrap().first().token_id == token_id;

        if is_vault_utxo {
            let value = bx.value;
            let tokens = if let Some(box_tokens) = bx.tokens {
                box_tokens.iter().skip(1).cloned().collect()
            } else {
                vec![]
            };
            Some(VaultUtxo { value, tokens })
        } else {
            None
        }
    }
}

impl From<&VaultUtxo> for SValue {
    fn from(value: &VaultUtxo) -> Self {
        let ergo_cell = ErgoCell {
            ergs: value.value,
            address: force_any_val(),
            tokens: value.tokens.clone(),
        };
        SValue::from(&ergo_cell)
    }
}
