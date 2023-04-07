use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

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

pub struct BinomialPeerPartitions<R> {
    // All peers ordered according to their VP at each level `l`.
    peers: Vec<Vec<PeerIx>>,
    rng_pd: PhantomData<R>,
}

impl<R> BinomialPeerPartitions<R>
where
    R: Rng,
{
    pub fn new(own_peer_id: PeerId, peers: Vec<PeerId>, mut rng: R) -> Self {
        let num_real_peers = <u32>::try_from(peers.len()).unwrap();
        let normalized_num_peers = normalize(num_real_peers);
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
        all_peers.shuffle(&mut rng);
        let own_index = all_peers
            .iter()
            .position(|pid| *pid == own_peer_id)
            .expect("Initial peer set must olways contain `own_peer_id`.");
        let partitions = bin_partition(own_index, all_peers.len());
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
            rng_pd: PhantomData::default(),
        }
    }
}

/// Partition peers binomially relative to `own_index`.
/// `num_peers` must be a power of 2.
fn bin_partition(own_index: usize, num_peers: usize) -> Vec<Vec<PeerIx>> {
    let mut partitions: Vec<Vec<PeerIx>> = vec![];
    let mut min = 0;
    let mut max = num_peers - 1;
    loop {
        let mid = min + (max - min) / 2;
        if own_index > mid {
            partitions.push((min..mid + 1).collect::<Vec<_>>());
            min = mid + 1;
        } else if own_index <= mid {
            partitions.push((mid + 1..max + 1).collect::<Vec<_>>());
            max = mid;
        };
        if min == max {
            break;
        }
    }
    partitions.reverse();
    partitions
}

/// Finds closes power of 2 to the given `n`.
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

impl<R> PeerPartitions for BinomialPeerPartitions<R> {
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use crate::protocol_handler::handel::partitioning::{bin_partition, normalize, BinomialPeerPartitions};

    #[test]
    fn test_normalization() {
        let test_vec = vec![(1, 1), (2, 2), (3, 4), (5, 8), (10, 16), (32, 32), (60, 64)];
        for (n, nn) in test_vec {
            assert_eq!(normalize(n), nn)
        }
    }

    #[test]
    fn test_bin_partitioning() {
        let augmented_peers = 16;
        let own_index_0 = 10;
        let part_0 = bin_partition(own_index_0, augmented_peers);
        assert_eq!(
            part_0,
            vec![
                vec![11],
                vec![8, 9],
                vec![12, 13, 14, 15],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
            ]
        );
        let own_index_1 = 4;
        let part_1 = bin_partition(own_index_1, augmented_peers);
        assert_eq!(
            part_1,
            vec![
                vec![5],
                vec![6, 7],
                vec![0, 1, 2, 3],
                vec![8, 9, 10, 11, 12, 13, 14, 15],
            ]
        );
    }

    #[test]
    fn test_instantiate_partitions() {
        let init_peers = (0..10).map(|_| PeerId::random()).collect::<Vec<_>>();
        let own_peer_id = init_peers[9];
        let seed = <ChaCha20Rng as SeedableRng>::Seed::from([0u8; 32]);
        let rng = ChaCha20Rng::from_seed(seed);
        let part = BinomialPeerPartitions::new(own_peer_id, init_peers.clone(), rng);
        assert_eq!(part.peers.len(), 4);
    }
}
