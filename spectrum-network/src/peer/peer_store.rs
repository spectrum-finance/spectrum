use libp2p::PeerId;
use std::collections::HashSet;

#[derive(Debug)]
pub enum PeerStoreRejection {
    StoreExhausted,
    AlreadyExists,
}

pub struct PeerSetConfig {
    pub max_outgoing: usize,
    pub max_incoming: usize,
}

pub struct PeerStoreConfig {
    pub capacity: usize,
}

pub struct PeerSet {
    connections_in: HashSet<PeerId>,
    connections_out: HashSet<PeerId>,
    config: PeerSetConfig,
}

impl PeerSet {
    pub fn new(config: PeerSetConfig) -> Self {
        Self {
            connections_in: HashSet::new(),
            connections_out: HashSet::new(),
            config,
        }
    }

    pub fn try_add_connection_out(&mut self, peer_id: PeerId) -> bool {
        if self.connections_out.len() < self.config.max_outgoing {
            self.connections_out.insert(peer_id);
            true
        } else {
            false
        }
    }
    pub fn try_add_connection_in(&mut self, peer_id: PeerId) -> bool {
        if self.connections_in.len() < self.config.max_incoming {
            self.connections_in.insert(peer_id);
            true
        } else {
            false
        }
    }
}
