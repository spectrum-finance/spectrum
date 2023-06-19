use std::collections::HashSet;
use std::ops::Range;

use libp2p::Multiaddr;
use libp2p_identity::PeerId;

use algebra_core::combinators::EitherOrBoth;
use itertools::EitherOrBoth;

pub struct TreeOverlay {
    parent_nodes: HashSet<PeerId>,
    child_nodes: Vec<(PeerId, Option<Multiaddr>)>,
}

impl TreeOverlay {
    pub fn new() -> Self {
        Self {
            parent_nodes: HashSet::new(),
            child_nodes: Vec::new(),
        }
    }
}

pub trait MakeTreeOverlay {
    fn make(
        &self,
        fixed_root_peer: Option<PeerId>,
        host_peer: PeerId,
        peers: Vec<(PeerId, Option<Multiaddr>)>,
    ) -> TreeOverlay;
}

pub struct RedundancyTreeOverlayBuilder {
    redundancy_factor: usize,
}

impl MakeTreeOverlay for RedundancyTreeOverlayBuilder {
    fn make(
        &self,
        fixed_root_peer: Option<PeerId>,
        host_peer: PeerId,
        mut peers: Vec<(PeerId, Option<Multiaddr>)>,
    ) -> TreeOverlay {
        peers.sort_by_key(|(pid, _)| pid);
        if let Some(root_peer) = fixed_root_peer {
            let ix = peers
                .iter()
                .position(|(pid, _)| *pid == root_peer)
                .expect("root must be in peer set");
            let root = peers.remove(ix);
            peers.insert(0, root);
        }
        let mut acc = TreeOverlay::new();
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
                if let Some(cl) = children.left() {
                    acc.child_nodes.push(cl);
                }
                if let Some(cr) = children.right() {
                    acc.child_nodes.push(cr);
                }
                acc.parent_nodes.insert(parent);
            }
            Links::LeafLinks { parent } => {
                acc.parent_nodes.insert(parent);
            }
        }
        return acc;
    }
}

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
                pt = (pt.1, pt.1 + 2.pow(cur_pt_ix))
            }
            if pid == host_peer {
                let ix_in_pt = cur_ix - pt.0;
                let parent_ix = prev_pt_lower + ix_in_pt / 2;
                return match peers.get(parent_ix) {
                    Some((parent_pid, _)) if parent_ix != cur_ix => {
                        let left_child_ix = 2 * ix_in_pt + pt.1;
                        let right_child_ix = left_child_ix_in_pt + 1 + pt.1;
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
                    _ => {
                        Links::RootLinks {
                            children: (peers.get(1).cloned(), peers.get(2).cloned()),
                        };
                    }
                };
            }
            cur_ix += 1;
        } else {
            panic!("Tree integrity violated");
        }
    }
}
