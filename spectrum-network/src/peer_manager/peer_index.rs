use crate::peer_manager::data::ConnectionDirection;
use crate::types::ProtocolId;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};

#[derive(Eq, PartialEq, Debug)]
pub struct PeerIndexConfig {
    pub max_outgoing: usize,
    pub max_incoming: usize,
}

#[derive(Debug)]
pub struct PeerIndex {
    pub reserved_peers: HashSet<PeerId>,
    pub enabled_connections: HashMap<PeerId, ConnectionDirection>,
    pub protocols: HashMap<ProtocolId, HashSet<PeerId>>,
    pub num_inbound: usize,
    pub num_outbound: usize,
    config: PeerIndexConfig,
}

impl PeerIndex {
    pub fn new(config: PeerIndexConfig) -> Self {
        Self {
            reserved_peers: HashSet::new(),
            enabled_connections: HashMap::new(),
            protocols: HashMap::new(),
            num_inbound: 0,
            num_outbound: 0,
            config,
        }
    }

    pub fn try_add_outgoing(&mut self, peer_id: PeerId) -> bool {
        if self.num_outbound < self.config.max_outgoing {
            self.enabled_connections
                .insert(peer_id, ConnectionDirection::Outbound(false));
            true
        } else {
            false
        }
    }

    pub fn confirm_outbound(&mut self, peer_id: PeerId) {
        self.enabled_connections
            .insert(peer_id, ConnectionDirection::Outbound(true));
    }

    pub fn try_add_incoming(&mut self, peer_id: PeerId) -> bool {
        if self.num_inbound < self.config.max_incoming {
            self.enabled_connections
                .insert(peer_id, ConnectionDirection::Inbound);
            true
        } else {
            false
        }
    }

    pub fn drop_outgoing(&mut self, peer_id: &PeerId) -> bool {
        self.num_outbound -= 1;
        self.enabled_connections.remove(peer_id).is_some()
    }

    pub fn drop_incoming(&mut self, peer_id: &PeerId) -> bool {
        self.num_inbound -= 1;
        self.enabled_connections.remove(peer_id).is_some()
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

    pub fn enable_protocol(&mut self, protocol_id: &ProtocolId, peer_id: PeerId) -> bool {
        if let Some(peers) = self.protocols.get_mut(protocol_id) {
            peers.insert(peer_id)
        } else {
            false
        }
    }

    pub fn is_protocol_enabled(&self, protocol_id: &ProtocolId, peer_id: &PeerId) -> bool {
        if let Some(peers) = self.protocols.get(protocol_id) {
            peers.contains(peer_id)
        } else {
            false
        }
    }
}
