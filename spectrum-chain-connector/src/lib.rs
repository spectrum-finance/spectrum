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

/// Outbound message from a Vault manager to consensus driver
pub enum VaultMsgOut {
    Status(VaultStatus),
    /// Indicates that the vault manager will begin sync'ing from the given ProgressPoint. If the
    /// consensus driver contains chain data prior to this point, delete it all and start from
    /// scratch.
    StartingSyncFrom(ProgressPoint),
    /// Sent when a new set of TXs are made on-chain for a given progress point.
    ApplyTxs {
        /// Value that is inbound to Spectrum-network
        imported_value: Vec<InboundValue>,
        /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
        exported_value: Vec<ProtoTermCell>,
        progress_point: ProgressPoint,
    },
    /// Sent when the chain experiences a rollback to the given progress point. Also contains
    /// exportation/importation of values to be reverted.
    Rollback {
        old_progress_point: ProgressPoint,
        reverted_imported_values: Vec<InboundValue>,
        reverted_exported_values: Vec<ProtoTermCell>,
    },
    /// This message contains a Vec of indices associated with the `txs` field in
    /// `VaultMsgIn::RequestTxsToNotarize`, where each indexed ProtoTermCell will
    /// be a part of the notarized report.
    ProposedTxsToNotarize(Vec<usize>),
}

/// Inbound message to a Vault manager from consensus driver
pub enum VaultMsgIn {
    /// Indicate to the vault manager to start rotating committee (WIP)
    RotateCommittee,
    /// Initiate transaction to settle exported value that's specified in the notarized report.
    ExportValue(Box<NotarizedReport>),
    /// Request the vault manager to find a set of TXs to notarize, subject to various constraints.
    RequestTxsToNotarize(NotarizedReportConstraints),
    /// Indicate to the vault manager to start sync'ing from the given progress point. If no
    /// progress point was given, then begin sync'ing from the oldest point known to the vault
    /// manager.
    SyncFrom(Option<ProgressPoint>),
}

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

pub enum VaultStatus {
    Synced(ProgressPoint),
    Syncing {
        current_progress_point: ProgressPoint,
        num_points_remaining: u32,
    },
}

pub struct Kilobytes(pub f32);

/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct InboundValue {
    pub value: SValue,
    pub owner: Owner,
    pub progress_point: ProgressPoint,
}

/// Represents an intention by Spectrum-network to create a `TermCell`.
#[derive(Clone)]
pub struct ProtoTermCell {
    pub value: SValue,
    pub dst: BoxDestination,
}

pub struct NotarizedReport {
    pub certificate: ReportCertificate,
    pub value_to_export: Vec<TermCell>,
    pub authenticated_digest: Vec<u8>,
}
