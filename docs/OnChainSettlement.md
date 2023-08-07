# Report notarization and on-chain settlement of outbound transactions

On this page we describe how the Spectrum-protocol settles outbound transactions on-chain. We define an _outbound transaction_ as one that transfers value from Spectrum to a user address in $S_k$.

Let us assume that the Spectrum protocol is running in the Normal Flow and consider a particular external system $S_k$ during epoch $e_n$ with a committee denoted by $V_n^k$ . For an arbitrary slot in this epoch, suppose that the committee members have been observing events in $S_k$  and the L+ mempool, leading to the slot leader to propose a batch or report of events in $S_k$ that we denote by $r^*$. The report $r^*$ consists of:
 - The _progress point_ of system $S_k$.
 - A list of effects on $S_k$. There are 4 types of effects:
	 1. Importation of value from $S_k$ into Spectrum's on-chain vault in $S_k$ (to be defined below).
	 2. Exportation of value from Spectrum's on-chain vault to a user address in $S_k$.
	 3. Revocation of a previously imported value due to a chain rollback in $S_k$.
	 4. Notification that $S_k$ has reached a particular progress point (e.g. new block height).
 - The hash value of the root of a Merkle tree formed by taking the above list of effects as leaf nodes. Note that we must define a partial order on these effects to enable proper verification (see appendix A).

### Report notarization

Once the slot leader has proposed a report $r^*$, it is disseminated to all committee members. Each committee member will recreate the Merkle tree from these effects and confirms that the root hash equals the hash within $r^*$. Then using $\mathcal{F}_{SIG}$, the committee computes the aggregated signature of the root hash value. We can then define the _notarized report_ $R^*$ as $r^*$ appended with the aggregated signature. $R^*$ is disseminated to all committee members.

```rust
struct NotarizedReport {
    certificate: ReportCertificate,
    value_to_export: Vec<(TermCell, rs_merkle::MerkleProof)>,
}
```

### Settlement of export-of-value effects on $S_k$

Let $I_k^0, I_k^1, \ldots, I_k^m$  denote the _ordered_ cell ids of all export-of-value effects in $R^*$ that are intended to be executed on $S_k$. Such effects are represented by a cell id $I_k^j$ that is associated with a _terminal_ cell $C_k^j$ in the system.

```rust
trait Vault {
    type ChainId;
    type PointUpdate;
    /// Initiate transactions to settle exported value that's specified in the notarized
    /// report.
    async fn export_value(&mut self, report: NotarizedReport) -> Result<(), VaultError>;
    /// Sync updates from given on-chain progress point.  
    async fn sync_progress_point(
        &mut self,
        updates: ProgressPointUpdates<Self::PointUpdate>,
    ) -> Result<Option<ProgressPoint>, VaultError>;
    /// Rollback to a previous progress point.
	async rollback_to(point: ProgressPoint);
}


struct ProgressPointUpdates<T>(ProgressPoint, Vec<T>);
```

### Appendix A: Partial order of effects

todo 