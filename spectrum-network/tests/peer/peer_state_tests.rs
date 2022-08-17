use libp2p::PeerId;
use spectrum_network::peer::peer_store::{PeerSetConfig, PeerStoreConfig};
use spectrum_network::peer::peers_state::{DefaultPeersState, PeersState};

#[test]
fn peer_state_should_correctly_add_peer() {
    let mut peer_state = mk_peers_state(4, 2, 10);
    let peer_id = PeerId::random();

    assert_eq!(peer_state.add_peer(peer_id, false).is_ok(), true);
    assert_eq!(peer_state.peer(&peer_id).is_some(), true);
}

#[test]
fn peer_state_should_correctly_forget_peer() {
    let mut peer_state = mk_peers_state(4, 2, 10);
    let peer_id = PeerId::random();

    let peer = peer_state.add_peer(peer_id, false);

    assert_eq!(peer.is_ok(), true);
    peer.unwrap().forget_peer();
    assert_eq!(peer_state.peer(&peer_id).is_none(), true);
}

fn mk_peers_state(max_incoming: usize, max_outgoing: usize, capacity: usize) -> impl PeersState {
    let pset_config = PeerSetConfig { max_incoming, max_outgoing };
    let pstore_config = PeerStoreConfig { capacity };
    DefaultPeersState::new(pset_config, pstore_config)
}
