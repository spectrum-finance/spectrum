use libp2p::PeerId;
use std::collections::HashSet;

#[derive(Eq, PartialEq, Debug)]
pub struct PeerSetsConfig {
    pub max_outgoing: usize,
    pub max_incoming: usize,
}

#[derive(Eq, PartialEq, Debug)]
pub struct PeerSets {
    connections_in: HashSet<PeerId>,
    connections_out: HashSet<PeerId>,
    reserved_peers: HashSet<PeerId>,
    config: PeerSetsConfig,
}

impl PeerSets {
    pub fn new(config: PeerSetsConfig) -> Self {
        Self {
            connections_in: HashSet::new(),
            connections_out: HashSet::new(),
            reserved_peers: HashSet::new(),
            config,
        }
    }

    pub fn try_add_outgoing(&mut self, peer_id: PeerId) -> bool {
        if self.connections_out.len() < self.config.max_outgoing {
            self.connections_out.insert(peer_id);
            true
        } else {
            false
        }
    }

    pub fn try_add_incoming(&mut self, peer_id: PeerId) -> bool {
        if self.connections_in.len() < self.config.max_incoming {
            self.connections_in.insert(peer_id);
            true
        } else {
            false
        }
    }

    pub fn drop_outgoing(&mut self, peer_id: &PeerId) -> bool {
        self.connections_out.remove(peer_id)
    }

    pub fn drop_incoming(&mut self, peer_id: &PeerId) -> bool {
        self.connections_in.remove(peer_id)
    }

    pub fn reserve_peer(&mut self, peer_id: PeerId) {
        self.reserved_peers.insert(peer_id);
    }

    pub fn drop_reserved_peer(&mut self, peer_id: &PeerId) {
        self.reserved_peers.remove(peer_id);
    }

    pub fn update_reserved_set(&mut self, peers: HashSet<PeerId>) {
        self.reserved_peers = peers;
    }
}
