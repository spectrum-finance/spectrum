use std::collections::HashSet;

use libp2p::Multiaddr;
use libp2p_identity::PeerId;
use rand::prelude::{SliceRandom, StdRng};
use rand::SeedableRng;

use algebra_core::combinators::EitherOrBoth;

#[derive(Clone, Debug)]
pub struct DagOverlay {
    pub parent_nodes: HashSet<PeerId>,
    pub child_nodes: Vec<(PeerId, Option<Multiaddr>)>,
}

impl DagOverlay {
    pub fn new() -> Self {
        Self {
            parent_nodes: HashSet::new(),
            child_nodes: Vec::new(),
        }
    }
}

pub trait MakeDagOverlay {
    fn make(
        &self,
        fixed_root_peer: Option<PeerId>,
        host_peer: PeerId,
        peers: Vec<(PeerId, Option<Multiaddr>)>,
    ) -> DagOverlay;
}

#[derive(Copy, Clone, Debug)]
pub struct RedundancyDagOverlayBuilder {
    pub redundancy_factor: usize,
    pub seed: u64,
}

impl MakeDagOverlay for RedundancyDagOverlayBuilder {
    fn make(
        &self,
        fixed_root_peer: Option<PeerId>,
        host_peer: PeerId,
        mut peers: Vec<(PeerId, Option<Multiaddr>)>,
    ) -> DagOverlay {
        peers.sort_by_key(|(pid, _)| *pid);
        if let Some(root_peer) = fixed_root_peer {
            let ix = peers
                .iter()
                .position(|(pid, _)| *pid == root_peer)
                .expect("root must be in peer set");
            let root = peers.remove(ix);
            peers.insert(0, root);
        }
        let mut acc = DagOverlay::new();
        let mut rng = StdRng::seed_from_u64(self.seed);
        for _ in 0..self.redundancy_factor {
            match build_links(host_peer, &peers) {
                Links::RootLinks { children } => {
                    if let Some(cl) = children.0 {
                        acc.child_nodes.push(cl);
                    }
                    if let Some(cr) = children.1 {
                        acc.child_nodes.push(cr);
                    }
                }
                Links::NodeLinks { parent, children } => {
                    children
                        .collect()
                        .into_iter()
                        .for_each(|c| acc.child_nodes.push(c));
                    acc.parent_nodes.insert(parent);
                }
                Links::LeafLinks { parent } => {
                    acc.parent_nodes.insert(parent);
                }
            }
            // Shuffle peerset after each pass so we can get N different trees.
            peers.shuffle(&mut rng)
        }
        return acc;
    }
}

#[derive(Debug)]
enum Links {
    RootLinks {
        children: (
            Option<(PeerId, Option<Multiaddr>)>,
            Option<(PeerId, Option<Multiaddr>)>,
        ),
    },
    NodeLinks {
        parent: PeerId,
        children: EitherOrBoth<(PeerId, Option<Multiaddr>), (PeerId, Option<Multiaddr>)>,
    },
    LeafLinks {
        parent: PeerId,
    },
}

fn build_links(host_peer: PeerId, peers: &Vec<(PeerId, Option<Multiaddr>)>) -> Links {
    let mut pt = (0usize, 1usize); // [lower, upper)
    let mut prev_pt_lower = 0;
    let mut cur_pt_ix = 0;
    let mut cur_ix = 0;
    loop {
        if let Some((pid, _)) = peers.get(cur_ix) {
            if cur_ix >= pt.1 {
                cur_pt_ix += 1;
                prev_pt_lower = pt.0;
                pt = (pt.1, pt.1 + 2usize.pow(cur_pt_ix))
            }
            if *pid == host_peer {
                let ix_in_pt = cur_ix - pt.0;
                let parent_ix = prev_pt_lower + ix_in_pt / 2;
                return match peers.get(parent_ix) {
                    Some((parent_pid, _)) if parent_ix != cur_ix => {
                        let left_child_ix = 2 * ix_in_pt + pt.1;
                        let right_child_ix = left_child_ix + 1;
                        if let Ok(children) = EitherOrBoth::try_from((
                            peers.get(left_child_ix).cloned(),
                            peers.get(right_child_ix).cloned(),
                        )) {
                            Links::NodeLinks {
                                parent: parent_pid.clone(),
                                children,
                            }
                        } else {
                            Links::LeafLinks {
                                parent: parent_pid.clone(),
                            }
                        }
                    }
                    _ => Links::RootLinks {
                        children: (peers.get(1).cloned(), peers.get(2).cloned()),
                    },
                };
            }
            cur_ix += 1;
        } else {
            panic!("Tree integrity violated");
        }
    }
}

#[cfg(test)]
mod tests {
    use libp2p_identity::PeerId;

    use crate::overlay::{build_links, Links, MakeDagOverlay, RedundancyDagOverlayBuilder};

    #[test]
    fn link_in_aligned_tree_leaf() {
        let peers = (0..15).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let host = peers[7].0;
        let links = build_links(host, &peers);
        assert!(matches!(links, Links::LeafLinks { .. }));
        match links {
            Links::LeafLinks { parent } => {
                assert_eq!(parent, peers[3].0);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn link_in_aligned_tree_root() {
        let peers = (0..15).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let host = peers[0].0;
        let links = build_links(host, &peers);
        assert!(matches!(links, Links::RootLinks { .. }));
        match links {
            Links::RootLinks { children } => {
                assert_eq!(
                    vec![children.0.unwrap(), children.1.unwrap()],
                    vec![peers[1].clone(), peers[2].clone()]
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn link_in_aligned_tree_node() {
        let peers = (0..15).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let host = peers[5].0;
        let links = build_links(host, &peers);
        assert!(matches!(links, Links::NodeLinks { .. }));
        match links {
            Links::NodeLinks { parent, children } => {
                assert_eq!(parent, peers[2].0);
                assert_eq!(children.collect(), vec![peers[11].clone(), peers[12].clone()]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn link_in_incomplete_tree_node() {
        let peers = (0..16).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let host = peers[7].0;
        let links = build_links(host, &peers);
        assert!(matches!(links, Links::NodeLinks { .. }));
        match links {
            Links::NodeLinks { parent, children } => {
                assert_eq!(parent, peers[3].0);
                assert_eq!(children.collect(), vec![peers[15].clone()]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn build_overlay() {
        let peers = (0..15).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let host = peers[0].0;
        let mut builder = RedundancyDagOverlayBuilder {
            redundancy_factor: 3,
            seed: 42,
        };
        let overlay = builder.make(None, host, peers);
        println!("{:?}", overlay);
    }
}
