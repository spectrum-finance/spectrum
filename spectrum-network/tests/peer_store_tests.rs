use crate::generators::generate_peer;
use libp2p::PeerId;
use spectrum_network::peer::data::{Peer, PeerInfo};
use spectrum_network::peer::peer_store::*;

mod generators;

#[test]
fn peer_store_should_correctly_add_peer() {
    let config = PeerStoreConfig::new(10);
    let mut peer_store = InMemoryPeerStore::empty(config);
    let peer_id = PeerId::random();

    let peer = generators::generate_peer();

    peer_store.add(&peer_id, peer.info.clone());

    let peer_in_store = peer_store.get(&peer_id).unwrap();

    assert_eq!(*peer_in_store, peer.info);
}

#[test]
#[should_panic]
fn peer_store_should_correctly_drop_peer() {
    let config = PeerStoreConfig::new(10);
    let mut peer_store = InMemoryPeerStore::empty(config);
    let peer_id = PeerId::random();

    let peer = generators::generate_peer();

    peer_store.add(&peer_id, peer.info.clone());

    peer_store.drop(&peer_id);

    let get_dropped_peer_status = peer_store.get(&peer_id);

    assert_eq!(get_dropped_peer_status.is_some(), true);
}

#[test]
fn peer_store_should_return_err_in_double_add() {
    let config = PeerStoreConfig::new(10);
    let mut peer_store = InMemoryPeerStore::empty(config);
    let peer_id = PeerId::random();

    let peer = generators::generate_peer();

    peer_store.add(&peer_id, peer.info.clone());

    let second_attempt_status = peer_store.add(&peer_id, peer.info.clone());

    assert_eq!(second_attempt_status.is_err(), true);
}

#[test]
#[should_panic]
fn peer_store_should_return_err_if_store_exhausted() {
    const CAPACITY: usize = 10;
    let config = PeerStoreConfig::new(CAPACITY);
    let mut peer_store = InMemoryPeerStore::empty(config);
    let peers: Vec<Peer> = (0..(CAPACITY + 1)).map(|_| generate_peer()).collect();

    for peer in peers {
        let peer_id = PeerId::random();
        peer_store.add(&peer_id, peer.info.clone()).unwrap();
    }
}
