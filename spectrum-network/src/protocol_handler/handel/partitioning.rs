use libp2p::PeerId;

/// Index of a peer withing Handel's range of peers.
pub type PeerIx = usize;

/// Does all the things related to partitioning of peer set withing Handel.
pub trait PeerPartitions {
    /// Gen peers at the specified level. Peers are ordered by verification priority.
    fn peers_at_level(&self, level: usize) -> Vec<PeerIx>;
    /// Match `PeerIx` with `PeerId`.
    fn identify_peer(&self, peer_ix: PeerIx) -> PeerId;
    /// Match `PeerId` with `PeerIx`.
    fn try_index_peer(&self, peer_ix: PeerId) -> Option<PeerIx>;
    /// Get the number of levels in this peer set.
    fn num_levels(&self) -> usize;
}
