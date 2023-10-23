# Report notarization and on-chain settlement of outbound transactions

On this page we describe how the Spectrum-protocol settles outbound
transactions on-chain. We define an _outbound transaction_ as one that
transfers value from Spectrum to a user address in $S_k$.

Let us assume that the Spectrum protocol is running in the Normal Flow and
consider a particular external system $S_k$ during epoch $e_n$ with a committee
denoted by $V_n^k$ . For an arbitrary slot in this epoch, suppose that the
committee members have been observing events in $S_k$  and the L+ mempool,
leading to the slot leader to propose a batch or report of events in $S_k$ that
we denote by $r^*$. The report $r^*$ consists of:
 - A list of _hashes_ of effects on $S_k$. There are 4 types of effects:
     1. Importation of value from $S_k$ into Spectrum's on-chain vault in $S_k$
     (to be defined below).
     2. Exportation of value from Spectrum's on-chain vault to a user address
     in $S_k$.
     3. Revocation of a previously imported value due to a chain rollback in
     $S_k$.
     4. Notification that $S_k$ has reached a particular progress point (e.g.
     new block height).
 - A _progress point_ $P_n^k$ of system $S_k$. It is assumed that _all_ of the
   listed effects included in $r^*$ are associated with a progress point $\le
   P_n^k$. Note that this progress point may not be the most recent from the
   viewpoint of the slot leader. By potentially choosing an older progress
   point, we increase the number of committee members that have observed all
   effects in the report.
 - A signature of $P_n^k$, signed by the slot leader's private key. 
 - A digest $D$ of a two-party authenticated data structure (e.g. merkle tree) that
   is constructed from the hashes of export-effects. By two-party, we mean a
   *prover* and a *verifier*. In our setting, the prover (in our case the slot
   leader) starts with an empty structure and performs operations to construct
   it while maintaining proofs of its construction. The verifier also starts
   from an empty structure and is given a proof, which is then used to construct
   data structure. Then a digest is computed and checked for equality with $D$.

### Report notarization

Once the slot leader has proposed a report $r^*$, it is disseminated to all
committee members. Each committee member will:
 1. Verify the progress point in $r^*$ using the slot leader's public key. If
    an honest committee member's view of $S_k$ is older than $P_n^k$ it may
    choose to not participate at all in the upcoming aggregation rounds.
 2. Confirm that each effect hash corresponds to a valid terminal cell
    belonging to its local pool of observed effects.
 3. Recreate the authenticated data structure from these effects and confirms
    that the resulting digest equals the digest within $r^*$. Then using
    $\mathcal{F}_{SIG}$, the committee computes the aggregated signature of the
    root hash value. We can then define the _notarized report_ $R^*$ as $r^*$
    appended with the aggregated signature. $R^*$ is disseminated to all
    committee members.

```rust
struct NotarizedReport {
    certificate: ReportCertificate,
    value_to_export: Vec<TermCell>,
    authenticated_digest: Vec<u8>,
}
```

### Settlement of export-of-value effects on $S_k$

Let $I^k_0, I^k_1, \ldots, I^k_m$  denote the _ordered_ cell ids of all
export-of-value effects in $R^*$ that are intended to be executed on $S_k$.
Such effects are represented by a cell id $I^k_j$ that is associated with a
_terminal_ cell $C^k_j$ in the system. Upon receiving the notarized report
$R^*$, the $S_k$-vault forms the associated transactions on-chain which are
guarded with a smart contract that performs the following validations:
 - Verify the aggregated signature $\sigma^k_n$ in the notarized report. Recall
   that the vault is guarded by the aggregated public key $\alpha PK_n^k$,
   which must be the same as the aggregated key of the current committee.
 - For each cell $C^k_j, j \in \{1, \ldots, m\}$, perform the proof to
   authenticate the existence of $C^k_j$ in the report.


### Vault API

```rust
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
    RequestTxsToNotarize {
        /// A collection of all pending outbound TXs.
        txs: Vec<ProtoTermCell>,
        /// The most recent progress point of a TX within `tx_set`.
        last_progress_point: ProgressPoint,
        /// Maximum TX size in kilobytes.
        max_tx_size: Kilobytes,
        /// An estimate of number of byzantine nodes in the current committee.
        estimated_number_of_byzantine_nodes: u32,
    },
    /// Indicate to the vault manager to start sync'ing from the given progress point. If no
    /// progress point was given, then begin sync'ing from the oldest point known to the vault
    /// manager.
    SyncFrom(Option<ProgressPoint>),
}

pub enum VaultStatus {
    Synced(ProgressPoint),
    Syncing {
        current_progress_point: ProgressPoint,
        num_points_remaining: u32,
    },
}

pub struct Kilobytes(u64);

/// Represents a value that is inbound to Spectrum-network on-chain.
pub struct InboundValue {
    pub value: SValue,
    pub owner: Owner,
    pub progress_point: ProgressPoint,
}

/// Represents an intention by Spectrum-network to create a `TermCell`.
pub struct ProtoTermCell {
    pub value: SValue,
    pub dst: BoxDestination,
}

pub struct NotarizedReport {
    pub certificate: ReportCertificate,
    pub value_to_export: Vec<TermCell>,
    pub authenticated_digest: Vec<u8>,
}

```