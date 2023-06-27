use move_core_types::identifier::Identifier;
use move_core_types::language_storage::TypeTag;
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_crypto::signature::Signature;
use spectrum_move::{SerializedModule, SerializedValue};

use crate::cell::{CellPtr, DatumRef, CellCore, ScriptRef, AnyCell, MutCell};
use crate::{ModifierId, SystemDigest};

/// Transaction processing pipeline:
/// `Transaction`          (linking   )-> `LinkedTransaction`
/// `LinkedTransaction`    (evaluation)-> `EvaluatedTransaction`
/// `EvaluatedTransaction` (validation)-> `[TransactionEffect]`
/// Transaction effects can be safely applied to the global ledger state.

/// Unverified transaction possibly containing yet unresolved inputs.
/// This is the only form of transaction that travels over the wire and goes on-chain,
/// that's why the size of this representation is optimized.
#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// Consumed boxes.
    pub inputs: Vec<(CellPtr, Option<u16>)>,
    /// Read-only inputs.
    pub reference_inputs: Vec<CellPtr>,
    /// Script invokations.
    pub invokations: Vec<ScriptInv>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<MutCell>,
    /// Aux data requred for transaction execution (e.g. scripts, data ..).
    pub witness: Witness,
}

impl Transaction {
    pub fn id(&self) -> ModifierId {
        todo!()
    }
}

impl SystemDigest for Transaction {
    fn digest(&self) -> Blake2bDigest256 {
        todo!() // todo: DEV-1034
    }
}

/// Unverified transaction whose inputs are resolved.
/// `Transaction` -> `LinkedTransaction`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LinkedTransaction {
    /// Consumed boxes.
    pub inputs: Vec<(AnyCell, Option<Signature>)>,
    /// Read-only inputs.
    pub reference_inputs: Vec<AnyCell>,
    /// Script invokations.
    pub invokations: Vec<LinkedScriptInv>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<MutCell>,
    /// Hash of the original transaction.
    pub hash: Blake2bDigest256,
}

/// Transaction whose inputs are verified and outputs are computed.
/// `Transaction` -> `LinkedTransaction` -> `EvaluatedTransaction`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EvaluatedTransaction {
    /// Consumed boxes.
    pub inputs: Vec<AnyCell>,
    /// Evaluated outputs.
    pub outputs: Vec<MutCell>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ScriptWitness {
    /// Reference to the existing on-chain box that contains the script.
    ScriptRef(ScriptRef),
    /// Script itself in serialized form.
    Script(SerializedModule),
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum DatumWitness {
    /// Reference to the existing on-chain box that contains the datum.
    DatumRef(DatumRef),
    /// Datum itself in serialized form.
    Datum(SerializedValue),
}

/// Auxilary data that don't have to be included into transaction hash.
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Witness {
    pub scripts: Vec<ScriptWitness>,
    pub data: Vec<DatumWitness>,
    pub signatures: Vec<Signature>,
}

/// Invokation of the owning script.
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScriptInv {
    /// Index of the script in the witness.
    pub script: u16,
    /// Index of the datum in the witness.
    /// `None` if datum is not required for script execution.
    pub datum: Option<u16>,
    pub function: Identifier,
    /// Arguments supplied to the function called.
    /// Note, these cannot be extracted into witness as long as
    /// they must be included into transaction hash.
    pub args: Vec<SerializedValue>,
    pub targs: Vec<TypeTag>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinkedScriptInv {
    pub script: SerializedModule,
    pub datum: Option<SerializedValue>,
    pub function: Identifier,
    /// Arguments supplied to the function called.
    pub args: Vec<SerializedValue>,
    pub targs: Vec<TypeTag>,
}
