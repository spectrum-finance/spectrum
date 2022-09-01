use libp2p::Multiaddr;
use spectrum_network::peer::data::*;

pub fn generate_peer() -> Peer {
    let info = PeerInfo::new(false);
    let addr: Multiaddr = "/ip4/1.2.3.4/tcp/1234".parse().unwrap();
    Peer { addr, info }
}
