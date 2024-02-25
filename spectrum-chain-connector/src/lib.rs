use serde::{Deserialize, Serialize};
use spectrum_ledger::cell::{ActiveCell, Serial};
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
/// Balance of the SN Vault on-chain.
pub struct VaultBalance<T> {
    pub value: SValue,
    pub on_chain_characteristics: T,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Outbound message from the Connector to consensus driver
pub enum ConnectorMsgOut<T, U, V> {
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
    /// Spectrum Network deposit transaction that spends deposit UTxOs and transfers its value into
    /// the SN Vault UTxO.
    Deposit {
        /// Value that is inbound to Spectrum-network
        imported_value: Vec<InboundValue<T>>,
        vault_balance: VaultBalance<U>,
    },

    /// Spectrum Network withdrawal transaction
    Withdrawal {
        /// Value that was successfully withdrawn from Spectrum-network to some recipient on-chain.
        withdrawn_value: Vec<TermCell>,
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
/// A response from the Connector to the consensus-driver that is sent after a `ConnectorRequest`
/// is received by the Connector.
///
/// The type variables are used for represent chain-specific information for a pending SN TX.
///  - Type variable `S` denotes chain-specific information associated with the notarized report
///    of a withdrawal TX.
///  - `T` denotes information relating to notarization bounds.
///  - `U` denotes chain-specific information to identify an inbound deposit to SN.
///  - `V` denotes chain-specific information relating to the SN Vault.
pub struct ConnectorResponse<S, T, U, V> {
    pub status: ConnectorStatus<S, U>,
    pub messages: Vec<ConnectorMsgOut<T, U, V>>,
}

/// Inbound message to Connector from consensus-driver.
///
/// The type variables are used for represent chain-specific information for a pending SN TX.
///  - Type variable `T` denotes chain-specific information associated with the notarized report
///    of a withdrawal TX.
///  - `U` denotes chain-specific information to identify an inbound deposit to SN.
#[derive(Deserialize, Serialize, Debug)]
pub enum ConnectorRequest<T, U> {
    /// Indicate to the Connector to start sync'ing from the given progress point. If no
    /// progress point was given, then begin sync'ing from the oldest point known to the vault
    /// manager.
    SyncFrom(Option<ProgressPoint>),
    /// Request the Connector to find a set of TXs to notarize, subject to various constraints.
    RequestTxsToNotarize(NotarizedReportConstraints),
    /// Request the connector to validate the given notarized report and if successful, form and
    /// submit a transaction to withdraw value to recipients that are specified in the notarized
    /// report.
    ValidateAndProcessWithdrawals(Box<NotarizedReport<T>>),
    /// Instruct the Connector form a TX to process outstanding deposits into SN.
    ProcessDeposits,
    /// Acknowledge that TX was confirmed.
    AcknowledgeConfirmedTx(PendingTxIdentifier<T, U>, ProgressPoint),
    /// Acknowledge that TX was aborted.
    AcknowledgeAbortedTx(PendingTxIdentifier<T, U>, ProgressPoint),
    /// Indicate to the Connector to start rotating committee (WIP)
    RotateCommittee,
    /// Indicate to Connector that consensus-driver is disconnecting.
    Disconnect,
}

#[derive(Deserialize, Serialize, Debug)]
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
/// Status of the Connector.
///
/// The type variables are used for represent chain-specific information for a pending SN TX.
///  - Type variable `T` denotes chain-specific information associated with the notarized report
///    of a withdrawal TX.
///  - `U` denotes chain-specific information to identify an inbound deposit to SN.
pub enum ConnectorStatus<T, U> {
    /// Indicates that the Connector is sync'ed (up to date) with its associated chain.
    Synced {
        /// The current progress point that the Connector is up to. It represents the
        /// tip of the chain at the time the struct is created.
        current_progress_point: ProgressPoint,
        /// Contains information on a pending TX (withdrawal or deposit), if it currently exists.
        pending_tx_status: Option<PendingTxStatus<T, U>>,
    },

    /// Indicates that the Connector has yet to complete sync'ing with its associated chain.
    Syncing {
        /// The current progress point that the Connector is up to.
        current_progress_point: ProgressPoint,
        /// The number of progress points remaining for the Connector to process to be in sync.
        num_points_remaining: u32,
        /// Contains information on a pending TX (withdrawal or deposit), if it currently exists.
        pending_tx_status: Option<PendingTxStatus<T, U>>,
    },
}

impl<T, U> ConnectorStatus<T, U>
where
    T: Clone,
    U: Clone,
{
    pub fn get_pending_tx_status(&self) -> Option<PendingTxStatus<T, U>> {
        match self {
            ConnectorStatus::Synced {
                pending_tx_status, ..
            }
            | ConnectorStatus::Syncing {
                pending_tx_status, ..
            } => pending_tx_status.clone(),
        }
    }

    pub fn get_current_progress_point(&self) -> ProgressPoint {
        match self {
            ConnectorStatus::Synced {
                current_progress_point,
                ..
            }
            | ConnectorStatus::Syncing {
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
pub struct PendingWithdrawalStatus<T> {
    pub identifier: NotarizedReport<T>,
    pub status: TxStatus,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct PendingDepositStatus<T> {
    pub identifier: Vec<InboundValue<T>>,
    pub status: TxStatus,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Represents the status of a pending SN TX.
///
/// Note on type variables:
///  - Type variable `T` denotes chain-specific information associated with the notarized report
///    of the withdrawal TX.
///  - `U` denotes chain-specific information to identify an inbound deposit to SN.
pub enum PendingTxStatus<T, U> {
    Withdrawal(PendingWithdrawalStatus<T>),
    Deposit(PendingDepositStatus<U>),
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum PendingTxIdentifier<T, U> {
    Withdrawal(Box<NotarizedReport<T>>),
    Deposit(Vec<InboundValue<U>>),
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Kilobytes(pub f32);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct InboundValue<T> {
    pub value: SValue,
    pub owner: Owner,
    pub on_chain_identifier: T,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Represents a confirmed inbound-value to Spectrum-network.
pub struct ConfirmedInboundValue {
    pub value: SValue,
    pub owner: Owner,
    pub tx_id: spectrum_ledger::transaction::TxId,
}

impl ConfirmedInboundValue {
    pub fn new<U>(value: InboundValue<U>, tx_id: spectrum_ledger::transaction::TxId) -> Self {
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

/// Represents an intention by Spectrum-Network to create a `TermCell`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProtoTermCell {
    pub value: SValue,
    pub dst: BoxDestination,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
pub struct NotarizedReport<T> {
    pub certificate: ReportCertificate,
    pub value_to_withdraw: Vec<TermCell>,
    pub authenticated_digest: Vec<u8>,
    pub additional_chain_data: T,
}
