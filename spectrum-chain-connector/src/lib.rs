use serde::{Deserialize, Serialize};
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
/// Outbound message from a Vault manager to consensus driver
pub enum VaultMsgOut {
    /// Indicates that the vault manager will begin sync'ing from the given ProgressPoint. If the
    /// consensus driver contains chain data prior to this point, delete it all and start from
    /// scratch.
    StartingSyncFrom(ProgressPoint),
    MovedValue(MovedValue),
    ProposedTxsToNotarize(Vec<usize>),
    ExportValueFailed,
}

/// Represents on-chain value of users that may be applied or rollback'ed on.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct UserValue {
    /// Value that is inbound to Spectrum-network
    pub imported_value: Vec<InboundValue>,
    /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
    pub exported_value: Vec<TermCell>,
    pub progress_point: ProgressPoint,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum MovedValue {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(UserValue),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(UserValue),
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VaultResponse {
    pub status: VaultStatus,
    pub messages: Vec<VaultMsgOut>,
}

/// Inbound message to a Vault manager from consensus driver
#[derive(Deserialize, Serialize)]
pub enum VaultRequest<T> {
    /// Indicate to the vault manager to start rotating committee (WIP)
    RotateCommittee,
    /// Initiate transaction to settle exported value that's specified in the notarized report.
    ExportValue(Box<NotarizedReport<T>>),
    /// Request the vault manager to find a set of TXs to notarize, subject to various constraints.
    RequestTxsToNotarize(NotarizedReportConstraints),
    /// Indicate to the vault manager to start sync'ing from the given progress point. If no
    /// progress point was given, then begin sync'ing from the oldest point known to the vault
    /// manager.
    SyncFrom(Option<ProgressPoint>),
    GetStatus,
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum VaultStatus {
    Synced(ProgressPoint),
    Syncing {
        current_progress_point: ProgressPoint,
        num_points_remaining: u32,
    },
}

#[derive(Deserialize, Serialize)]
pub struct Kilobytes(pub f32);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct InboundValue {
    pub value: SValue,
    pub owner: Owner,
    pub progress_point: ProgressPoint,
}

/// Represents an intention by Spectrum-network to create a `TermCell`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProtoTermCell {
    pub value: SValue,
    pub dst: BoxDestination,
}

#[derive(Deserialize, Serialize)]
pub struct NotarizedReport<T> {
    pub certificate: ReportCertificate,
    pub value_to_export: Vec<TermCell>,
    pub authenticated_digest: Vec<u8>,
    pub additional_chain_data: T,
}
