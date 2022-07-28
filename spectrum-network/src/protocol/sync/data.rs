use libp2p::PeerId;

pub struct PeerSync {
    pub peer_id: PeerId,
    pub sync_state: PeerSyncStatus
}

pub enum PeerSyncStatus {
    Available,
    Busy,
}
