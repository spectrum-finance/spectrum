use libp2p::PeerId;

/// Partitions peers by levels in binomial tree from the point of view of `self_id`.
pub fn partition_binomial(peers: Vec<PeerId>, seed: [u8; 32], self_id: PeerId) -> Vec<Vec<PeerId>> {
    vec![vec![]]
}

pub trait PeerPartitions {
    fn peers_at_level(&self, level: usize) -> Vec<>
}
