use std::collections::{HashMap, HashSet};

use libp2p::PeerId;
use rand::prelude::SliceRandom;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Index of a peer withing Handel's range of peers.
pub type PeerIx = usize;

/// Does all the things related to partitioning of peer set withing Handel.
pub trait PeerPartitions {
    /// Gen peers at the specified level. Peers are ordered by verification priority.
    fn peers_at_level(&self, level: usize) -> Vec<PeerIx>;
    /// Match `PeerIx` with `PeerId`.
    fn identify_peer(&self, peer_ix: PeerIx) -> PeerId;
    /// Match `PeerId` with `PeerIx`.
    fn try_index_peer(&self, peer_id: PeerId) -> Option<PeerIx>;
    /// Get the number of levels in this peer set.
    fn num_levels(&self) -> usize;
}

pub struct BinomialPeerPartitions {
    // All peers ordered according to their VP at each level `l`.
    peers: Vec<Vec<PeerIx>>,
}

impl BinomialPeerPartitions {
    pub fn new(own_peer_id: PeerId, peers: Vec<PeerId>, seed: [u8; 32]) -> Self {
        let num_real_peers = <u32>::try_from(peers.len()).unwrap();
        println!("0");
        let normalized_num_peers = normalize(num_real_peers);
        println!("1");
        let num_fake_peers = normalized_num_peers - num_real_peers;
        let fake_peers = (0..num_fake_peers)
            .into_iter()
            .map(|_| PeerId::random())
            .collect::<HashSet<_>>();
        let mut all_peers = peers
            .clone()
            .into_iter()
            .chain(fake_peers.clone())
            .collect::<Vec<_>>();
        all_peers.sort();
        let seed = <ChaCha20Rng as SeedableRng>::Seed::from(seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        all_peers.shuffle(&mut rng);
        println!("2");
        let own_index = all_peers
            .iter()
            .position(|pid| *pid == own_peer_id)
            .expect("Initial peer set must olways contain `own_peer_id`.");
        let partitions = bin_partition(own_index, all_peers.len());
        println!("3");
        let cleared_partitions = partitions
            .into_iter()
            .map(|pt| {
                pt.into_iter()
                    .filter(|pix| !fake_peers.contains(&all_peers[*pix]))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Self {
            peers: cleared_partitions,
        }
    }
}

fn bin_partition(own_index: usize, num_peers: usize) -> Vec<Vec<PeerIx>> {
    let mut partitions: Vec<Vec<PeerIx>> = vec![];
    let mut min = 0;
    let mut max = num_peers;
    let mut i = 0u32;
    loop {
        if i > 20 { break }
        i += 1;
        let mid = max / 2;
        let this_level = if own_index > mid {
            min = mid + 1;
            (min..mid).collect::<Vec<_>>()
        } else if own_index < mid {
            max = mid;
            (mid + 1..max).collect::<Vec<_>>()
        } else {
            break;
        };
        partitions.push(this_level);
    }
    partitions
}

fn normalize(n: u32) -> u32 {
    let mut power = 0u32;
    loop {
        let p = 2u32.pow(power);
        if n <= p {
            return p;
        } else {
            power += 1;
        }
    }
}

impl PeerPartitions for BinomialPeerPartitions {
    fn peers_at_level(&self, level: usize) -> Vec<PeerIx> {
        todo!()
    }

    fn identify_peer(&self, peer_ix: PeerIx) -> PeerId {
        todo!()
    }

    fn try_index_peer(&self, peer_id: PeerId) -> Option<PeerIx> {
        todo!()
    }

    fn num_levels(&self) -> usize {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;

    use crate::protocol_handler::handel::partitioning::{normalize, BinomialPeerPartitions, bin_partition};

    #[test]
    fn test_normalization() {
        let test_vec = vec![(1, 1), (2, 2), (3, 4), (5, 8), (10, 16), (32, 32), (60, 64)];
        for (n, nn) in test_vec {
            assert_eq!(normalize(n), nn)
        }
    }

    #[test]
    fn test_bin_partitioning() {
        let own_index = 9;
        let total_peers = 10;
        let part = bin_partition(own_index, total_peers);
        println!("Partitioned peers: {:?}", part);
    }

    #[test]
    fn test_instantiate_partitions() {
        let init_peers = (0..10).map(|_| PeerId::random()).collect::<Vec<_>>();
        let own_peer_id = init_peers[9];
        let seed = [0u8; 32];
        let part = BinomialPeerPartitions::new(own_peer_id, init_peers.clone(), seed);
        println!("Init peers: {:?}", init_peers);
        println!("Partitioned peers: {:?}", part.peers);
    }
}
