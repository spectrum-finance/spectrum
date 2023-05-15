use k256::schnorr::Signature;

use move_core_types::identifier::Identifier;
use move_core_types::language_storage::TypeTag;
use spectrum_move::{SerializedModule, SerializedValue};

use crate::sbox::{BoxId, BoxRef, DatumRef, PolicyId, SBox, ScriptRef};

/// Transaction processing pipeline:
/// `Transaction`          (linking   )-> `LinkedTransaction`
/// `LinkedTransaction`    (evaluation)-> `EvaluatedTransaction`
/// `EvaluatedTransaction` (validation)-> `[TransactionEffect]`
/// Transaction effects can be safely applied to the global ledger state.

/// Unverified transaction possibly containing yet unresolved inputs.
/// This is the only form of transaction that travels over the wire and goes on-chain,
/// that's why the size of this representation is optimized.
pub struct Transaction {
    /// Inputs the transaction can manipulate.
    pub inputs: Vec<Input>,
    /// Read-only inputs.
    pub reference_inputs: Vec<InputTarget>,
    /// Value minting within the transaction.
    pub minting_inputs: Vec<MintingInput>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<SBox>,
    /// Aux data requred for transaction execution (e.g. scripts, data ..).
    pub witness: Witness,
}

/// Unverified transaction whose inputs are resolved.
/// `Transaction` -> `LinkedTransaction`
pub struct LinkedTransaction {
    /// Inputs the transaction can manipulate.
    pub inputs: Vec<LinkedInput>,
    /// Read-only inputs.
    pub reference_inputs: Vec<SBox>,
    /// Value minting within the transaction.
    pub minting_inputs: Vec<LinkedMintingInput>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<SBox>,
}

/// Transaction whose inputs are verified and outputs are computed.
/// `Transaction` -> `LinkedTransaction` -> `EvaluatedTransaction`
pub struct EvaluatedTransaction {
    /// Inputs the transaction can manipulate.
    pub inputs: Vec<SBox>,
    /// Read-only inputs.
    pub reference_inputs: Vec<SBox>,
    /// Evaluated outputs.
    pub outputs: Vec<SBox>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ScriptWitness {
    /// Reference to the existing on-chain box that contains the script.
    ScriptRef(ScriptRef),
    /// Script itself in serialized form.
    Script(SerializedModule),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum DatumWitness {
    /// Reference to the existing on-chain box that contains the datum.
    DatumRef(DatumRef),
    /// Datum itself in serialized form.
    Datum(SerializedValue),
}

/// Auxilary data that don't have to be included into transaction hash.
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Witness {
    pub scripts: Vec<ScriptWitness>,
    pub data: Vec<DatumWitness>,
    pub signatures: Vec<Signature>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub enum InputTarget {
    BoxId(BoxId),
    BoxRef(BoxRef),
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Redeemer {
    /// Proof of knowledge of dlog.
    Signature(/*sig_index_in_witness*/ u16),
    /// Invokation of the owning script.
    ScriptInv {
        /// Index of the script in the witness.
        script: u16,
        /// Index of the datum in the witness.
        /// `None` if datum is not required for script execution.
        datum: Option<u16>,
        function: Identifier,
        /// Arguments supplied to the function called.
        /// Note, these cannot be extracted into witness as long as
        /// they must be included into transaction hash.
        args: Vec<SerializedValue>,
        targs: Vec<TypeTag>,
    },
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum LinkedRedeemer {
    /// Proof of knowledge of dlog.
    Signature(Signature),
    /// Invokation of the owning script.
    ScriptInv {
        script: SerializedModule,
        datum: Option<SerializedValue>,
        function: Identifier,
        /// Arguments supplied to the function called.
        args: Vec<SerializedValue>,
        targs: Vec<TypeTag>,
    },
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Input {
    pub target: InputTarget,
    pub redeemer: Redeemer,
}

/// Input whose target is resolved.
/// `Input` -> `LinkedInput`
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LinkedInput {
    pub target: SBox,
    pub redeemer: LinkedRedeemer,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct MintingInput {
    pub target: PolicyId,
    pub redeemer: Redeemer,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LinkedMintingInput {
    pub target: PolicyId,
    pub redeemer: LinkedRedeemer,
}
