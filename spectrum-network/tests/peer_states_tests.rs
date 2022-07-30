use libp2p::PeerId;
use spectrum_network::peer::peer_store::{InMemoryPeerStore, PeerStoreConfig};
use spectrum_network::peer::peers_state::{DefaultPeersState, PeersState};

#[test]
fn peer_state_should_correctly_add_peer() {
    let config = PeerStoreConfig::new(10);
    let peer_store = InMemoryPeerStore::empty(config);
    let mut peer_state = DefaultPeersState::new(peer_store);
    let peer_id = PeerId::random();

    assert_eq!(peer_state.add_peer(&peer_id, false).is_ok(), true);
    assert_eq!(peer_state.get_peer(&peer_id).is_some(), true);
}

#[test]
fn peer_state_should_correctly_forget_peer() {
    let config = PeerStoreConfig::new(10);
    let peer_store = InMemoryPeerStore::empty(config);
    let mut peer_state = DefaultPeersState::new(peer_store);
    let peer_id = PeerId::random();

    assert_eq!(peer_state.add_peer(&peer_id, false).is_ok(), true);
    assert_eq!(peer_state.forget_peer(&peer_id), true);
    assert_eq!(peer_state.get_peer(&peer_id).is_none(), true);
}
