use libp2p::PeerId;
use spectrum_network::peer_manager::{
    data::PeerDestination,
    peers_state::{PeerRepo, PeersState},
    NetworkingConfig,
};

#[test]
fn should_add_peer() {
    let mut peer_state = mk_peers_state(4, 2, 10);
    let peer_id = PeerDestination::PeerId(PeerId::random());

    assert!(peer_state.try_add_peer(peer_id.clone(), false, false).is_some());
    assert!(peer_state.peer(&peer_id.peer_id()).is_some());
}

#[test]
fn should_forget_peer() {
    let mut peer_state = mk_peers_state(4, 2, 10);
    let peer_id = PeerDestination::PeerId(PeerId::random());

    let peer = peer_state.try_add_peer(peer_id.clone(), false, false);

    assert!(peer.is_some());
    peer.unwrap().forget();
    assert!(peer_state.peer(&peer_id.peer_id()).is_none());
}

#[test]
fn should_connect_to_peer_when_vacant_connections_available() {
    let mut peer_state = mk_peers_state(4, 2, 10);
    let peer_id = PeerDestination::PeerId(PeerId::random());

    let peer = peer_state.try_add_peer(peer_id, false, false);
    let _ = peer.unwrap().connect();
}

#[test]
fn err_connect_to_peer_when_vacant_connections_not_available() {
    let mut peer_state = mk_peers_state(0, 0, 10);
    let peer_id = PeerDestination::PeerId(PeerId::random());

    let peer = peer_state.try_add_peer(peer_id, false, false).unwrap();
    let _connected_peer = peer.connect();
    //assert!(peer.connect().is_err());
}

fn mk_peers_state(max_inbound: usize, max_outbound: usize, capacity: usize) -> impl PeersState {
    let netw_conf = NetworkingConfig {
        min_known_peers: 2,
        min_outbound: 1,
        max_inbound,
        max_outbound,
    };
    let boot_peers = vec![
        PeerDestination::PeerId(PeerId::random()),
        PeerDestination::PeerId(PeerId::random()),
        PeerDestination::PeerId(PeerId::random()),
    ];
    PeerRepo::new(netw_conf, boot_peers)
}
