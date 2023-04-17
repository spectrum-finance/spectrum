use std::collections::{HashMap, HashSet};

use derive_more::From;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Index of a peer within Handel's range of peers.
/// Always maps to some `PeerId` within Handel overlay.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, From, Debug, Serialize, Deserialize)]
pub struct PeerIx(usize);

impl PeerIx {
    pub fn unwrap(&self) -> usize {
        self.0
    }
}

pub enum PeerOrd {
    VP,
    CVP,
}

pub trait GenPermutation {
    fn gen_priority(&self, peer_id: PeerId) -> u128;
    fn gen_vp(&self, host_peer_ix: PeerIx, peer_ix: PeerIx) -> u128;
}

#[derive(Clone)]
pub struct PseudoRandomGenPerm {
    seed: TSeed,
}

impl PseudoRandomGenPerm {
    pub fn new(seed: TSeed) -> Self {
        Self { seed }
    }
}

impl GenPermutation for PseudoRandomGenPerm {
    fn gen_priority(&self, peer_id: PeerId) -> u128 {
        let hasher = Sha256::new()
            .chain_update(self.seed.to_vec())
            .chain_update(peer_id.to_bytes());
        let result = hasher.finalize();
        hash256_to_u128(&result[..])
    }

    fn gen_vp(&self, host_peer_ix: PeerIx, peer_ix: PeerIx) -> u128 {
        let hasher = Sha256::new()
            .chain_update(self.seed.to_vec())
            .chain_update(host_peer_ix.0.to_be_bytes())
            .chain_update(peer_ix.0.to_be_bytes());
        let result = hasher.finalize();
        hash256_to_u128(&result[..])
    }
}

fn hash256_to_u128(hash: &[u8]) -> u128 {
    let u128 = hash[..16]
        .to_vec()
        .iter()
        .zip(hash[16..].to_vec())
        .map(|(l, r)| l ^ r)
        .collect::<Vec<_>>();
    <u128>::from_be_bytes(<[u8; 16]>::try_from(u128).unwrap())
}

/// Does all the things related to partitioning of peer set withing Handel.
pub trait PeerPartitions {
    /// Gen peers at the specified level. Peers are ordered by verification priority.
    fn peers_at_level(&self, level: usize, ord: PeerOrd) -> Vec<PeerIx>;
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
    /// All peers partitioned and ordered according to their VP at each level `l`.
    partitions_by_vp: Vec<Vec<PeerIx>>,
    /// All peers partitioned and ordered according to their CVP at each level `l`.
    partitions_by_cvp: Vec<Vec<PeerIx>>,
    rng: R,
}

type TSeed = [u8; 32];

impl<R> BinomialPeerPartitions<R>
where
    R: GenPermutation,
{
    pub fn new(host_peer_id: PeerId, peers: Vec<PeerId>, rng: R) -> Self {
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
        all_peers.sort_by_key(|pid| rng.gen_priority(*pid));
        let total_index = all_peers
            .iter()
            .enumerate()
            .map(|(ix, pid)| (*pid, PeerIx(ix)))
            .collect::<HashMap<_, _>>();
        let host_peer_ix = all_peers
            .iter()
            .position(|pid| *pid == host_peer_id)
            .map(PeerIx)
            .expect("Initial peer set must always contain `host_peer_id`.");
        let num_nodes = all_peers.len();
        let partitions = bin_partition(host_peer_ix.0, num_nodes);
        let cleared_partitions = partitions
            .into_iter()
            .map(|pt| {
                pt.into_iter()
                    .filter(|pix| !fake_peers.contains(&all_peers[pix.unwrap()]))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Self {
            peers: all_peers,
            peer_index: total_index,
            partitions_by_vp: ordered_by_vp(&rng, cleared_partitions.clone(), host_peer_ix),
            partitions_by_cvp: ordered_by_cvp(&rng, cleared_partitions, host_peer_ix, num_nodes),
            rng,
        }
    }
}

/// Arrange peers within partitions according to their VP.
fn ordered_by_vp<R: GenPermutation>(
    rng: &R,
    partitions: Vec<Vec<PeerIx>>,
    host_peer_ix: PeerIx,
) -> Vec<Vec<PeerIx>> {
    let mut ordered_partitions = vec![];
    for mut pt in partitions {
        pt.sort_by_key(|pix| rng.gen_vp(host_peer_ix, *pix));
        ordered_partitions.push(pt);
    }
    ordered_partitions
}

fn ordered_by_cvp<R: GenPermutation>(
    rng: &R,
    partitions: Vec<Vec<PeerIx>>,
    host_peer_ix: PeerIx,
    num_nodes: usize,
) -> Vec<Vec<PeerIx>> {
    let mut ordered_partitions = vec![];
    for (l, mut pt) in partitions.into_iter().enumerate() {
        pt.sort_by_key(|pix| {
            // We have to compute peer's view of the level `l` to find out host's priority.
            let pt = &mut bin_partition(pix.unwrap(), num_nodes)[l];
            pt.sort_by_key(|pix0| rng.gen_vp(*pix, *pix0));
            pt.into_iter().position(|ix| *ix == host_peer_ix).unwrap()
        });
        ordered_partitions.push(pt);
    }
    ordered_partitions
}

/// Partition peers binomially relative to `own_index`.
/// `num_peers` must be a power of 2.
fn bin_partition(own_index: usize, num_nodes: usize) -> Vec<Vec<PeerIx>> {
    let mut partitions: Vec<Vec<PeerIx>> = vec![];
    let mut min = 0;
    let mut max = num_nodes - 1;
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
    // 0'th partition is always empty bacause it contains only the host node itself.
    // Nevertheless it must be present in the partitioning table
    // in order for it to be coherent with level indexing.
    partitions.push(vec![]);
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
    fn peers_at_level(&self, level: usize, ord: PeerOrd) -> Vec<PeerIx> {
        match ord {
            PeerOrd::VP => self.partitions_by_vp[level].clone(),
            PeerOrd::CVP => self.partitions_by_cvp[level].clone(),
        }
    }

    fn identify_peer(&self, peer_ix: PeerIx) -> PeerId {
        self.peers[peer_ix.unwrap()]
    }

    fn try_index_peer(&self, peer_id: PeerId) -> Option<PeerIx> {
        self.peer_index.get(&peer_id).copied()
    }

    fn num_levels(&self) -> usize {
        self.partitions_by_vp.len()
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use libp2p::PeerId;

    use crate::protocol_handler::handel::partitioning::{
        bin_partition, normalize, BinomialPeerPartitions, PeerIx, PeerOrd, PeerPartitions,
        PseudoRandomGenPerm,
    };

    pub struct FakePartitions {
        peers: Vec<PeerId>,
        peer_index: HashMap<PeerId, PeerIx>,
        partitions: Vec<Vec<PeerIx>>,
    }

    impl FakePartitions {
        pub fn new(partitions: Vec<Vec<PeerId>>) -> Self {
            let mut flat_peers = partitions.iter().flatten().collect::<Vec<_>>();
            flat_peers.sort();
            let mut peers = flat_peers
                .iter()
                .enumerate()
                .map(|(ix, pid)| (PeerIx(ix), **pid))
                .collect::<Vec<_>>();
            peers.sort_by_key(|(pix, _)| *pix);
            let index = HashMap::from_iter(peers.iter().map(|(pix, pid)| (*pid, *pix)));
            Self {
                peers: peers.into_iter().map(|(_, pid)| pid).collect(),
                peer_index: index.clone(),
                partitions: partitions
                    .into_iter()
                    .map(|pt| pt.into_iter().map(|pid| *index.get(&pid).unwrap()).collect())
                    .collect(),
            }
        }
    }

    impl PeerPartitions for FakePartitions {
        fn peers_at_level(&self, level: usize, ord: PeerOrd) -> Vec<PeerIx> {
            self.partitions[level].clone()
        }

        fn identify_peer(&self, peer_ix: PeerIx) -> PeerId {
            self.peers[peer_ix.unwrap()]
        }

        fn try_index_peer(&self, peer_id: PeerId) -> Option<PeerIx> {
            self.peer_index.get(&peer_id).copied()
        }

        fn num_levels(&self) -> usize {
            self.partitions.len()
        }
    }

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
                vec![],
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
                vec![],
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
        let rng = PseudoRandomGenPerm::new([0u8; 32]);
        let part = BinomialPeerPartitions::new(own_peer_id, init_peers.clone(), rng);
        assert_eq!(part.partitions_by_vp.len(), 5);
        println!("{:?}", part.partitions_by_vp);
    }

    #[test]
    fn overlay_structure_is_coherent_across_peers() {
        let init_peers = (0..16).map(|_| PeerId::random()).collect::<Vec<_>>();
        let host_id = init_peers[9];
        let peer_id = init_peers[15];
        let rng = PseudoRandomGenPerm::new([0u8; 32]);
        let host_pp = BinomialPeerPartitions::new(host_id, init_peers.clone(), rng.clone());
        let peer_pp = BinomialPeerPartitions::new(peer_id, init_peers.clone(), rng);
        let host_ix_peer = peer_pp.try_index_peer(host_id).unwrap();
        let host_ix_host = host_pp.try_index_peer(host_id).unwrap();
        let peer_ix_host = host_pp.try_index_peer(peer_id).unwrap();
        let peer_ix_peer = peer_pp.try_index_peer(peer_id).unwrap();
        assert_eq!(host_ix_peer, host_ix_host);
        assert_eq!(peer_ix_host, peer_ix_peer);
        // Peers are in the same partition.
        assert_eq!(
            host_pp
                .partitions_by_cvp
                .iter()
                .position(|pt| pt.contains(&peer_ix_host)),
            peer_pp
                .partitions_by_vp
                .iter()
                .position(|pt| pt.contains(&host_ix_peer))
        );
    }

    fn as_peer_indexes(xs: Vec<Vec<usize>>) -> Vec<Vec<PeerIx>> {
        xs.into_iter()
            .map(|ls| ls.into_iter().map(PeerIx).collect())
            .collect()
    }
}
