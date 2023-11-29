use std::collections::HashMap;

use ergo_lib::ergo_chain_types::ec_point::{generator, identity};
use ergo_lib::ergo_chain_types::EcPoint;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergo_lib::ergotree_ir::chain::ergo_box::{
    ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
};
use ergo_lib::ergotree_ir::mir::constant::{Constant, Literal};
use ergo_lib::ergotree_ir::mir::value::{CollKind, NativeColl};
use ergo_lib::ergotree_ir::types::stype::SType;
use ergo_lib::{chain::transaction::TxIoVec, ergotree_ir::ergo_tree::ErgoTree};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_offchain::event_sink::handlers::types::{IntoBoxCandidate, TryFromBoxCtx};
use spectrum_offchain_lm::data::AsBox;

pub struct CommitteeData {
    pub first_box: AsBox<FirstCommitteeBox>,
    pub subsequent_boxes: Option<TxIoVec<AsBox<SubsequentCommitteeBox>>>,
}

pub struct FirstCommitteeBox {
    pub public_keys: Vec<EcPoint>,
    pub vault_parameters: VaultParameters,
    pub committee_hash: Blake2bDigest256,
    pub guarding_script: ErgoTree,
    pub box_value: BoxValue,
}

/// ErgoTree is guarding script
impl TryFromBoxCtx<(ErgoTree, &[EcPoint])> for FirstCommitteeBox {
    fn try_from_box(bx: ErgoBox, (guarding_script, expected_keys): (ErgoTree, &[EcPoint])) -> Option<Self> {
        if bx.ergo_tree == guarding_script {
            println!("GUARDING SCRIPT FINE");
            let committee_index = extract_committee_index(&bx)?;
            if committee_index != 0 {
                return None;
            }
            let public_keys = extract_committee_keys(&bx, expected_keys)?;
            println!("BBB");
            let vault_parameters = extract_vault_parameters(&bx)?;
            println!("CCC");
            let committee_hash = extract_committee_hash(&bx)?;
            println!("DDD");
            extract_group_elements(&bx)?;
            println!("EEE");
            Some(FirstCommitteeBox {
                public_keys,
                vault_parameters,
                committee_hash,
                guarding_script,
                box_value: bx.value,
            })
        } else {
            None
        }
    }
}

impl IntoBoxCandidate for FirstCommitteeBox {
    fn into_candidate(self, height: u32) -> ErgoBoxCandidate {
        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: Literal::from(self.public_keys),
        };
        let mut registers = HashMap::new();
        registers.insert(NonMandatoryRegisterId::R4, serialized_committee);
        registers.insert(NonMandatoryRegisterId::R5, 0.into());
        registers.insert(NonMandatoryRegisterId::R6, self.vault_parameters.into());
        registers.insert(NonMandatoryRegisterId::R7, Constant::from(generator()));
        registers.insert(
            NonMandatoryRegisterId::R8,
            Constant::from(EcPoint::from(k256::ProjectivePoint::IDENTITY)),
        );
        registers.insert(
            NonMandatoryRegisterId::R9,
            Constant::from(self.committee_hash.as_ref().to_vec()),
        );
        ErgoBoxCandidate {
            value: self.box_value,
            ergo_tree: self.guarding_script,
            tokens: None,
            additional_registers: NonMandatoryRegisters::new(registers).unwrap(),
            creation_height: height,
        }
    }
}

pub struct SubsequentCommitteeBox {
    pub public_keys: Vec<EcPoint>,
    pub index: u32,
    pub guarding_script: ErgoTree,
    pub box_value: BoxValue,
}

impl TryFromBoxCtx<(BoxValue, ErgoTree, u32, &[EcPoint])> for SubsequentCommitteeBox {
    fn try_from_box(
        bx: ErgoBox,
        (box_value, guarding_script, index, expected_keys): (BoxValue, ErgoTree, u32, &[EcPoint]),
    ) -> Option<Self> {
        if bx.ergo_tree == guarding_script {
            let committee_index = extract_committee_index(&bx)? as u32;
            if committee_index != index {
                return None;
            }
            let public_keys = extract_committee_keys(&bx, expected_keys)?;
            Some(SubsequentCommitteeBox {
                public_keys,
                index,
                guarding_script,
                box_value,
            })
        } else {
            None
        }
    }
}

impl IntoBoxCandidate for SubsequentCommitteeBox {
    fn into_candidate(self, height: u32) -> ErgoBoxCandidate {
        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: Literal::from(self.public_keys),
        };
        let mut registers = HashMap::new();
        registers.insert(NonMandatoryRegisterId::R4, serialized_committee);
        registers.insert(NonMandatoryRegisterId::R5, 0.into());

        ErgoBoxCandidate {
            value: self.box_value,
            ergo_tree: self.guarding_script,
            tokens: None,
            additional_registers: NonMandatoryRegisters::new(registers).unwrap(),
            creation_height: height,
        }
    }
}

/// Stores parameters associated with the vault.
pub struct VaultParameters {
    /// The number of UTXOs that exist to store committee information.
    pub num_committee_boxes: i32,
    /// Current epoch number.
    pub current_epoch: i32,
    /// Epoch length as measured by number of blocks.
    pub epoch_length: i32,
    /// Starting block height of the Vault
    pub vault_starting_height: i32,
}

impl From<VaultParameters> for Constant {
    fn from(value: VaultParameters) -> Self {
        let v = vec![
            value.num_committee_boxes,
            value.current_epoch,
            value.epoch_length,
            value.vault_starting_height,
        ];
        Constant::from(v)
    }
}

fn extract_committee_keys(ergo_box: &ErgoBox, expected_keys: &[EcPoint]) -> Option<Vec<EcPoint>> {
    let Ok(Some(r4)) = ergo_box.get_register(NonMandatoryRegisterId::R4.into()) else {
        return None;
    };
    let Literal::Coll(CollKind::WrappedColl {
        elem_tpe: SType::SGroupElement,
        items,
    }) = &r4.v
    else {
        return None;
    };

    let mut keys = vec![];
    for (literal, expected_key) in items.iter().zip(expected_keys) {
        let Literal::GroupElement(point) = literal else {
            return None;
        };
        let key = point.as_ref().clone();
        if key != *expected_key {
            return None;
        }
        keys.push(key);
    }
    Some(keys)
}

fn extract_vault_parameters(bx: &ErgoBox) -> Option<VaultParameters> {
    let Ok(Some(r6)) = bx.get_register(NonMandatoryRegisterId::R6.into()) else {
        return None;
    };
    let Literal::Coll(CollKind::WrappedColl {
        elem_tpe: SType::SInt,
        items,
    }) = &r6.v
    else {
        return None;
    };

    if items.len() != 4 {
        return None;
    }
    let Literal::Int(num_committee_boxes) = items[0] else {
        return None;
    };
    let Literal::Int(current_epoch) = items[1] else {
        return None;
    };
    let Literal::Int(epoch_length) = items[2] else {
        return None;
    };
    let Literal::Int(vault_starting_height) = items[3] else {
        return None;
    };

    Some(VaultParameters {
        num_committee_boxes,
        current_epoch,
        epoch_length,
        vault_starting_height,
    })
}

fn extract_committee_index(ergo_box: &ErgoBox) -> Option<i32> {
    let Ok(Some(r5)) = ergo_box.get_register(NonMandatoryRegisterId::R5.into()) else {
        return None;
    };
    let Literal::Int(index) = r5.v else {
        return None;
    };
    Some(index)
}

fn extract_group_elements(bx: &ErgoBox) -> Option<(EcPoint, EcPoint)> {
    let Ok(Some(r7)) = bx.get_register(NonMandatoryRegisterId::R7.into()) else {
        return None;
    };

    let Literal::GroupElement(point) = &r7.v else {
        return None;
    };

    // In R7 we expect there to be the generator element of secp256k1
    let gen = generator();
    if *point.as_ref() != gen {
        return None;
    }

    let Ok(Some(r8)) = bx.get_register(NonMandatoryRegisterId::R8.into()) else {
        return None;
    };

    let Literal::GroupElement(point) = &r8.v else {
        return None;
    };

    let id = identity();

    // We expect R8 to contain the identity element of secp256k1
    if *point.as_ref() != id {
        return None;
    }

    Some((gen, id))
}

fn extract_committee_hash(bx: &ErgoBox) -> Option<Blake2bDigest256> {
    let Ok(Some(r9)) = bx.get_register(NonMandatoryRegisterId::R9.into()) else {
        return None;
    };

    let Literal::Coll(CollKind::NativeColl(NativeColl::CollByte(bytes_i8))) = &r9.v else {
        return None;
    };

    let bytes: Vec<u8> = bytes_i8.iter().map(|b| *b as u8).collect();
    Blake2bDigest256::try_from(bytes).ok()
}
