use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use derive_more::From;
use libp2p::PeerId;
use rand::prelude::SliceRandom;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};

/// Index of a peer within Handel's range of peers.
/// Always maps to some `PeerId` within Handel overlay.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, From, Debug)]
pub struct PeerIx(usize);

impl PeerIx {
    pub fn index(&self) -> usize {
        self.0
    }
}

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
    /// Peers ordered within Handel overlay.
    peers: Vec<PeerId>,
    /// Index for quick identification of peers within the overlay.
    peer_index: HashMap<PeerId, PeerIx>,
    /// All peers ordered according to their VP at each level `l`.
    partititons: Vec<Vec<PeerIx>>,
    rng_pd: PhantomData<R>,
}

type TSeed = [u8; 32];

impl<R> BinomialPeerPartitions<R>
where
    R: Rng + SeedableRng<Seed = TSeed>,
{
    pub fn new(own_peer_id: PeerId, peers: Vec<PeerId>, seed: TSeed) -> Self {
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
        let mut rng = R::from_seed(seed);
        all_peers.sort();
        all_peers.shuffle(&mut rng);
        let total_index = all_peers
            .iter()
            .enumerate()
            .map(|(ix, pid)| (*pid, PeerIx(ix)))
            .collect::<HashMap<_, _>>();
        let own_index = all_peers
            .iter()
            .position(|pid| *pid == own_peer_id)
            .expect("Initial peer set must always contain `own_peer_id`.");
        let partitions = bin_partition(own_index, all_peers.len());
        let cleared_partitions = partitions
            .into_iter()
            .map(|pt| {
                pt.into_iter()
                    .filter(|pix| !fake_peers.contains(&all_peers[pix.index()]))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Self {
            peers: all_peers,
            peer_index: total_index,
            partititons: Self::ordered_by_vp(cleared_partitions, seed, own_peer_id),
            rng_pd: PhantomData::default(),
        }
    }

    /// Arrange peers withing partitions according to their VP.
    fn ordered_by_vp(partitions: Vec<Vec<PeerIx>>, seed: TSeed, own_peer_id: PeerId) -> Vec<Vec<PeerIx>> {
        let mut vp_rng = Self::vp_rng(seed, own_peer_id);
        let mut ordered_partitions = vec![];
        for mut pt in partitions {
            pt.shuffle(&mut vp_rng);
            ordered_partitions.push(pt);
        }
        ordered_partitions
    }

    fn vp_rng(seed: TSeed, own_peer_id: PeerId) -> R {
        let mut hasher = Sha256::new();
        let xs = seed
            .to_vec()
            .into_iter()
            .chain(own_peer_id.to_bytes())
            .collect::<Vec<u8>>();
        hasher.update(xs);
        let result = hasher.finalize();
        R::from_seed(<TSeed>::try_from(result).unwrap())
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
            partitions.push((min..mid + 1).map(PeerIx).collect());
            min = mid + 1;
        } else if own_index <= mid {
            partitions.push((mid + 1..max + 1).map(PeerIx).collect());
            max = mid;
        };
        if min == max {
            break;
        }
    }
    partitions.reverse();
    partitions
}

/// Finds closest power of 2 following the given `n`.
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
        self.partititons[level].clone()
    }

    fn identify_peer(&self, peer_ix: PeerIx) -> PeerId {
        self.peers[peer_ix.index()]
    }

    fn try_index_peer(&self, peer_id: PeerId) -> Option<PeerIx> {
        self.peer_index.get(&peer_id).copied()
    }

    fn num_levels(&self) -> usize {
        self.partititons.len()
    }
}

#[cfg(test)]
mod tests {
    use libp2p::PeerId;
    use rand_chacha::ChaCha20Rng;

    use crate::protocol_handler::handel::partitioning::{
        bin_partition, normalize, BinomialPeerPartitions, PeerIx,
    };

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
            as_peer_indexes(vec![
                vec![11],
                vec![8, 9],
                vec![12, 13, 14, 15],
                vec![0, 1, 2, 3, 4, 5, 6, 7],
            ])
        );
        let own_index_1 = 4;
        let part_1 = bin_partition(own_index_1, augmented_peers);
        assert_eq!(
            part_1,
            as_peer_indexes(vec![
                vec![5],
                vec![6, 7],
                vec![0, 1, 2, 3],
                vec![8, 9, 10, 11, 12, 13, 14, 15],
            ])
        );
    }

    #[test]
    fn test_instantiate_partitions() {
        let init_peers = (0..10).map(|_| PeerId::random()).collect::<Vec<_>>();
        let own_peer_id = init_peers[9];
        let seed = [0u8; 32];
        let part = BinomialPeerPartitions::<ChaCha20Rng>::new(own_peer_id, init_peers.clone(), seed);
        assert_eq!(part.partititons.len(), 4);
        println!("{:?}", part.partititons);
    }

    fn as_peer_indexes(xs: Vec<Vec<usize>>) -> Vec<Vec<PeerIx>> {
        xs.into_iter()
            .map(|ls| ls.into_iter().map(PeerIx).collect())
            .collect()
    }
}
