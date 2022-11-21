use crate::peer_manager::data::ConnectionDirection;
use crate::types::ProtocolId;
use libp2p::PeerId;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct PeerIndex {
    pub reserved_peers: HashSet<PeerId>,
    pub boot_peers: HashSet<PeerId>,
    pub enabled_connections: HashMap<PeerId, ConnectionDirection>,
    pub protocols: HashMap<ProtocolId, HashSet<PeerId>>,
    pub num_inbound: usize,
    pub num_outbound: usize,
}

impl PeerIndex {
    pub fn new() -> Self {
        Self {
            reserved_peers: HashSet::new(),
            boot_peers: HashSet::new(),
            enabled_connections: HashMap::new(),
            protocols: HashMap::new(),
            num_inbound: 0,
            num_outbound: 0,
        }
    }

    pub fn add_outgoing(&mut self, peer_id: PeerId) {
        self.enabled_connections
            .insert(peer_id, ConnectionDirection::Outbound(false));
    }

    pub fn confirm_outbound(&mut self, peer_id: PeerId) {
        self.enabled_connections
            .insert(peer_id, ConnectionDirection::Outbound(true));
    }

    pub fn add_incoming(&mut self, peer_id: PeerId) {
        self.enabled_connections
            .insert(peer_id, ConnectionDirection::Inbound);
    }

    pub fn drop_outgoing(&mut self, peer_id: &PeerId, is_boot: bool) {
        self.num_outbound = self.num_outbound.saturating_sub(1);
        self.enabled_connections.remove(peer_id);
        if is_boot {
            self.boot_peers.remove(peer_id);
        }
    }

    pub fn drop_incoming(&mut self, peer_id: &PeerId) -> bool {
        self.num_inbound = self.num_inbound.saturating_sub(1);
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

impl Default for PeerIndex {
    fn default() -> Self {
        Self::new()
    }
}
