use std::collections::HashMap;

use k256::schnorr::Signature;

use crate::sbox::{BoxId, BoxRef, DatumHash, PolicyId, SBox, ScriptHash, ScriptRef};

pub struct Transaction {
    /// Inputs the transaction can manipulate.
    pub inputs: Vec<Input>,
    /// Read-only inputs.
    pub reference_inputs: Vec<InputTarget>,
    /// Value minting within the transaction.
    pub minting_inputs: Vec<MintingInput>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<SBox>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ScriptWitness {
    ScriptRef(ScriptRef),
    Script(), // todo
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum DatumWitness {
    DatumRef(ScriptRef),
    Datum(), // todo
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Witness {
    pub scripts: HashMap<ScriptHash, ScriptWitness>,
    pub data: HashMap<DatumHash, DatumWitness>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub enum InputTarget {
    BoxId(BoxId),
    BoxRef(BoxRef),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Redeemer {
    Signature(Signature),
    ScriptInv {
        /// Script reference
        script_ref: Option<ScriptRef>,
        // args, targs
    },
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Input {
    pub target: InputTarget,
    pub redeemer: Redeemer,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct MintingInput {
    pub target: PolicyId,
    pub redeemer: Redeemer,
}
