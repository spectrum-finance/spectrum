use crate::peer::data::PeerInfo;
use libp2p::PeerId;
use std::collections::HashMap;

#[derive(Debug)]
pub enum PeerStoreRejection {
    StoreExhausted,
    AlreadyExists,
}

pub trait PeerStore {
    fn add(
        &mut self,
        peer_id: &PeerId,
        peer: PeerInfo,
    ) -> Result<&mut PeerInfo, PeerStoreRejection>;
    fn drop(&mut self, peer_id: &PeerId) -> bool;
    fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo>;
    fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo>;
}

pub struct PeerStoreConfig {
    capacity: usize,
}

impl PeerStoreConfig {
    pub fn new(capacity: usize) -> Self {
        PeerStoreConfig { capacity }
    }
}

pub struct InMemoryPeerStore {
    peers: HashMap<PeerId, PeerInfo>,
    conf: PeerStoreConfig,
}

impl InMemoryPeerStore {
    pub fn empty(config: PeerStoreConfig) -> Self {
        InMemoryPeerStore {
            peers: HashMap::new(),
            conf: config,
        }
    }

    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }
}

impl PeerStore for InMemoryPeerStore {
    fn add(
        &mut self,
        peer_id: &PeerId,
        peer: PeerInfo,
    ) -> Result<&mut PeerInfo, PeerStoreRejection> {
        if self.peers.len() < self.conf.capacity {
            if self.peers.contains_key(&peer_id) {
                Err(PeerStoreRejection::AlreadyExists)
            } else {
                Ok(self.peers.entry(peer_id.clone()).or_insert(peer))
            }
        } else {
            Err(PeerStoreRejection::StoreExhausted)
        }
    }

    fn drop(&mut self, peer_id: &PeerId) -> bool {
        self.peers.remove(peer_id).is_some()
    }

    fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }
}
