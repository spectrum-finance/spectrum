use std::{iter, vec};

use nonempty::NonEmpty;

use move_core_types::identifier::Identifier;
use move_core_types::language_storage::TypeTag;
use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_crypto::signature::Signature;
use spectrum_move::{SerializedModule, SerializedValue};

use crate::cell::{CellPtr, CellRef, DatumRef, InputCell, OutputCell, ScriptRef};
use crate::SystemDigest;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
)]
pub struct TxId(Blake2bDigest256);

/// Transaction processing pipeline:
/// `Transaction`          (linking   )-> `LinkedTransaction`
/// `LinkedTransaction`    (evaluation)-> `EvaluatedTransaction`
/// `EvaluatedTransaction` (validation)-> `[TransactionEffect]`
/// Transaction effects can be safely applied to the global ledger state.

/// Non-empty set of inputs.
/// First input is always fully qualified.
#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxInputs {
    /// TX must have at least one fully qualified input.
    pub head: (CellRef, Option<u16>),
    /// Other inputs referenced by pointers.
    pub tail: Vec<(CellPtr, Option<u16>)>,
}

impl IntoIterator for TxInputs {
    type Item = (CellPtr, Option<u16>);
    type IntoIter = iter::Chain<iter::Once<Self::Item>, vec::IntoIter<Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        let (hd_ref, hd_sig) = self.head;
        iter::once((CellPtr::Ref(hd_ref), hd_sig)).chain(self.tail)
    }
}

impl From<TxInputs> for NonEmpty<(CellPtr, Option<u16>)> {
    fn from(
        TxInputs {
            head: (cref, sig),
            tail,
        }: TxInputs,
    ) -> Self {
        NonEmpty {
            head: (CellPtr::Ref(cref), sig),
            tail,
        }
    }
}

/// Unverified transaction possibly containing yet unresolved inputs.
/// This is the only form of transaction that travels over the wire and goes on-chain,
/// that's why the size of this representation is optimized.
#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    /// Consumed boxes.
    pub inputs: TxInputs,
    /// Read-only inputs.
    pub reference_inputs: Vec<CellPtr>,
    /// Script invokations.
    pub invokations: Vec<ScriptInv>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<OutputCell>,
    /// Aux data requred for transaction execution (e.g. scripts, data ..).
    pub witness: Witness,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TransactionWithoutWitness {
    /// Consumed boxes.
    pub inputs: TxInputs,
    /// Read-only inputs.
    pub reference_inputs: Vec<CellPtr>,
    /// Script invokations.
    pub invokations: Vec<ScriptInv>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<OutputCell>,
}

impl From<Transaction> for TransactionWithoutWitness {
    fn from(
        Transaction {
            inputs,
            reference_inputs,
            invokations,
            evaluated_outputs,
            ..
        }: Transaction,
    ) -> Self {
        Self {
            inputs,
            reference_inputs,
            invokations,
            evaluated_outputs,
        }
    }
}

impl Transaction {
    fn bytes_without_witness(&self) -> Vec<u8> {
        let tx = TransactionWithoutWitness::from(self.clone());
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&tx, &mut encoded).unwrap();
        encoded
    }
}

impl Transaction {
    pub fn id(&self) -> TxId {
        TxId::from(self.digest())
    }
}

impl SystemDigest for Transaction {
    fn digest(&self) -> Blake2bDigest256 {
        blake2b256_hash(&*self.bytes_without_witness())
    }
}

/// Unverified transaction whose inputs are resolved.
/// `Transaction` -> `LinkedTransaction`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct LinkedTransaction {
    /// Consumed boxes.
    pub inputs: Vec<(InputCell, Option<Signature>)>,
    /// Read-only inputs.
    pub reference_inputs: Vec<InputCell>,
    /// Script invokations.
    pub invokations: Vec<LinkedScriptInv>,
    /// Statically evaluated outputs.
    pub evaluated_outputs: Vec<OutputCell>,
    /// Hash of the original transaction.
    pub hash: Blake2bDigest256,
}

/// Transaction whose inputs are verified and outputs are computed.
/// `Transaction` -> `LinkedTransaction` -> `EvaluatedTransaction`
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EvaluatedTransaction {
    /// Consumed boxes.
    pub inputs: Vec<InputCell>,
    /// Evaluated outputs.
    pub outputs: Vec<OutputCell>,
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
