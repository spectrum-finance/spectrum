use serde::{Deserialize, Serialize};
use spectrum_ledger::cell::{ActiveCell, Serial};
use spectrum_ledger::transaction::TxId;
use spectrum_ledger::{
    cell::{BoxDestination, Owner, ProgressPoint, SValue, TermCell},
    interop::ReportCertificate,
};

#[derive(Clone, Debug)]
pub enum TxEvent<T> {
    AppliedTx(T),
    UnappliedTx(T),
}

pub trait DataBridge {
    type TxType;
    fn get_components(self) -> DataBridgeComponents<Self::TxType>;
}

pub struct DataBridgeComponents<T> {
    /// Each consumer of the data bridge is given a receiver to stream transaction data.
    pub receiver: tokio::sync::mpsc::Receiver<TxEvent<T>>,
    /// Call `send(())` on this `Sender` to indicate that the bridge should start transmitting
    /// transaction data. Note that the receivers should have already been distributed to
    /// consumers.
    pub start_signal: tokio::sync::oneshot::Sender<()>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct VaultBalance<T> {
    pub value: SValue,
    pub on_chain_characteristics: T,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Outbound message from a Vault manager to consensus driver
pub enum VaultMsgOut<T, U, V> {
    TxEvent(ChainTxEvent<U, V>),
    ProposedTxsToNotarize(T),
    GenesisVaultUtxo(SValue),
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct SpectrumTx<T, U> {
    pub progress_point: ProgressPoint,
    pub tx_type: SpectrumTxType<T, U>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum SpectrumTxType<T, U> {
    /// Spectrum Network deposit transaction
    Deposit {
        /// Value that is inbound to Spectrum-network
        imported_value: Vec<InboundValue<T>>,
        vault_balance: VaultBalance<U>,
    },

    /// Spectrum Network withdrawal transaction
    Withdrawal {
        /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
        exported_value: Vec<TermCell>,
        vault_balance: VaultBalance<U>,
    },

    NewUnprocessedDeposit(InboundValue<T>),
    RefundedDeposit(InboundValue<T>),
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ChainTxEvent<T, U> {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(SpectrumTx<T, U>),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(SpectrumTx<T, U>),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VaultResponse<S, T, U, V> {
    pub status: VaultStatus<S, U>,
    pub messages: Vec<VaultMsgOut<T, U, V>>,
}

/// Inbound message to a Vault manager from consensus driver
#[derive(Deserialize, Serialize)]
pub enum VaultRequest<T, U> {
    /// Indicate to the vault manager to start sync'ing from the given progress point. If no
    /// progress point was given, then begin sync'ing from the oldest point known to the vault
    /// manager.
    SyncFrom(Option<ProgressPoint>),
    /// Request the vault manager to find a set of TXs to notarize, subject to various constraints.
    RequestTxsToNotarize(NotarizedReportConstraints),
    /// Initiate transaction to settle exported value that's specified in the notarized report.
    ExportValue(Box<NotarizedReport<T>>),
    /// Instruct the vault-manager to process deposits.
    ProcessDeposits,
    /// Acknowledge that TX was confirmed.
    AcknowledgeConfirmedTx(PendingTxIdentifier<T, U>, ProgressPoint),
    /// Acknowledge that TX was aborted.
    AcknowledgeAbortedTx(PendingTxIdentifier<T, U>, ProgressPoint),
    /// Indicate to the vault manager to start rotating committee (WIP)
    RotateCommittee,
}

#[derive(Deserialize, Serialize)]
pub struct NotarizedReportConstraints {
    /// A collection of all pending outbound TXs.
    pub term_cells: Vec<ProtoTermCell>,
    /// The most recent progress point of a TX within `tx_set`.
    pub last_progress_point: ProgressPoint,
    /// Maximum TX size in kilobytes.
    pub max_tx_size: Kilobytes,
    /// An estimate of number of byzantine nodes in the current committee.
    pub estimated_number_of_byzantine_nodes: u32,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum VaultStatus<T, U> {
    Synced {
        current_progress_point: ProgressPoint,
        pending_tx_status: Option<PendingTxStatus<T, U>>,
    },
    Syncing {
        current_progress_point: ProgressPoint,
        num_points_remaining: u32,
        pending_tx_status: Option<PendingTxStatus<T, U>>,
    },
}

impl<T, U> VaultStatus<T, U>
where
    T: Clone,
    U: Clone,
{
    pub fn get_pending_tx_status(&self) -> Option<PendingTxStatus<T, U>> {
        match self {
            VaultStatus::Synced {
                pending_tx_status, ..
            }
            | VaultStatus::Syncing {
                pending_tx_status, ..
            } => pending_tx_status.clone(),
        }
    }

    pub fn get_current_progress_point(&self) -> ProgressPoint {
        match self {
            VaultStatus::Synced {
                current_progress_point,
                ..
            }
            | VaultStatus::Syncing {
                current_progress_point,
                ..
            } => current_progress_point.clone(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum TxStatus {
    WaitingForConfirmation,
    Confirmed,
    Aborted,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PendingExportStatus<T> {
    pub identifier: NotarizedReport<T>,
    pub status: TxStatus,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PendingDepositStatus<T> {
    pub identifier: Vec<InboundValue<T>>,
    pub status: TxStatus,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum PendingTxStatus<T, U> {
    Export(PendingExportStatus<T>),
    Deposit(PendingDepositStatus<U>),
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum PendingTxIdentifier<T, U> {
    Export(Box<NotarizedReport<T>>),
    Deposit(Vec<InboundValue<U>>),
}

#[derive(Deserialize, Serialize)]
pub struct Kilobytes(pub f32);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct InboundValue<T> {
    pub value: SValue,
    pub owner: Owner,
    pub on_chain_identifier: T,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct ConfirmedInboundValue {
    pub value: SValue,
    pub owner: Owner,
    pub tx_id: TxId,
}

impl ConfirmedInboundValue {
    pub fn new<U>(value: InboundValue<U>, tx_id: TxId) -> Self {
        Self {
            value: value.value,
            owner: value.owner,
            tx_id,
        }
    }
}

impl From<ConfirmedInboundValue> for ActiveCell {
    fn from(value: ConfirmedInboundValue) -> Self {
        ActiveCell {
            value: value.value,
            owner: value.owner,
            datum: None,
            reference_script: None,
            reference_datum: None,
            // TBD when Spectrum Network chain is complete
            tx_id: value.tx_id,
            index: 0,
            ver: Serial::INITIAL,
        }
    }
}

/// Represents an intention by Spectrum-network to create a `TermCell`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProtoTermCell {
    pub value: SValue,
    pub dst: BoxDestination,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NotarizedReport<T> {
    pub certificate: ReportCertificate,
    pub value_to_export: Vec<TermCell>,
    pub authenticated_digest: Vec<u8>,
    pub additional_chain_data: T,
}
