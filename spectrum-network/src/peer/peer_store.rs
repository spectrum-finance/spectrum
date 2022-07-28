use libp2p::PeerId;
use std::collections::HashMap;
use crate::peer::data::{PeerInfo};

pub enum PeerStoreRejection {
    StoreExhausted,
    AlreadyExists,
}

pub trait PeerStore {
    fn add(&mut self, peer_id: &PeerId, peer: PeerInfo) -> Result<&mut PeerInfo, PeerStoreRejection>;
    fn drop(&mut self, peer_id: &PeerId) -> bool;
    fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo>;
    fn get_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo>;
}

pub struct PeerStoreConfig {
    capacity: usize,
}

pub struct InMemoryPeerStore {
    peers: HashMap<PeerId, PeerInfo>,
    conf: PeerStoreConfig,
}

impl PeerStore for InMemoryPeerStore {
    fn add(&mut self, peer_id: &PeerId, peer: PeerInfo) -> Result<&mut PeerInfo, PeerStoreRejection> {
        if self.peers.len() < self.conf.capacity {
            if self.peers.contains_key(&peer_id) {
                Err(PeerStoreRejection::AlreadyExists)
            } else {
                self.peers.insert(peer_id.clone(), peer);
                Ok(self.peers.get_mut(&peer_id).unwrap())
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

#[cfg(test)]
mod tests {
    #[test]
    fn full_slots_in() {}
}
