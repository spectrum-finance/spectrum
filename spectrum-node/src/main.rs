use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;
use std::time::Duration;

use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::identity;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use libp2p::PeerId;

use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::data::PeerDestination;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig};
use spectrum_network::protocol::{ProtocolConfig, ProtocolSpec, SYNC_PROTOCOL_ID};
use spectrum_network::protocol_handler::sync::message::{SyncMessage, SyncMessageV1, SyncSpec};
use spectrum_network::protocol_handler::sync::{NodeStatus, SyncBehaviour};
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::Reputation;

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("conf/log4rs.yaml", Default::default()).unwrap();

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    let transport = libp2p::development_transport(local_key).await?;

    let mut boot_peers = Vec::new();
    // Dial the peer identified by the multi-address given as the second
    // command-line argument, if any.
    println!(
        "{:?}",
        (
            std::env::args().nth(1),
            std::env::args().nth(2),
            std::env::args().nth(3)
        )
    );
    if let (Some(pid), Some(addr)) = (std::env::args().nth(2), std::env::args().nth(3)) {
        if !pid.starts_with("--") {
            let remote: Multiaddr = addr.parse()?;
            boot_peers.push(PeerDestination::PeerIdWithAddr(
                FromStr::from_str(pid.as_str()).unwrap(),
                remote,
            ))
        }
    }

    let peer_conn_handler_conf = PeerConnHandlerConf {
        async_msg_buffer_size: 10,
        sync_msg_buffer_size: 40,
        open_timeout: Duration::from_secs(60),
        initial_keep_alive: Duration::from_secs(60),
    };
    let netw_config = NetworkingConfig {
        min_known_peers: 1,
        min_outbound: 1,
        max_inbound: 10,
        max_outbound: 20,
    };
    let peer_manager_conf = PeerManagerConfig {
        min_acceptable_reputation: Reputation::from(0),
        min_reputation: Reputation::from(0),
        conn_reset_outbound_backoff: Duration::from_secs(120),
        conn_alloc_interval: Duration::from_secs(30),
        prot_alloc_interval: Duration::from_secs(30),
        protocols_allocation: Vec::new(),
    };
    let peer_state = PeerRepo::new(netw_config, boot_peers);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let sync_conf = ProtocolConfig {
        supported_versions: vec![(
            SyncSpec::v1(),
            ProtocolSpec {
                max_message_size: 100,
                approve_required: true,
            },
        )],
    };

    let local_status = NodeStatus {
        supported_protocols: Vec::from([SYNC_PROTOCOL_ID]),
        height: 0,
    };
    let sync_behaviour = SyncBehaviour::new(peers.clone(), local_status);
    let (requests_snd, requests_recv) = mpsc::unbounded::<NetworkControllerIn>();
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };
    let (mut sync_handler, sync_mailbox) = ProtocolHandler::new(sync_behaviour, network_api);
    let nc = NetworkController::new(
        peer_conn_handler_conf,
        HashMap::from([(SYNC_PROTOCOL_ID, (sync_conf, sync_mailbox))]),
        peers,
        peer_manager,
        requests_recv,
    );

    let mut swarm = SwarmBuilder::with_async_std_executor(transport, nc, local_peer_id).build();

    swarm.listen_on(std::env::args().nth(1).unwrap().parse()?)?;

    async_std::task::spawn(async move {
        loop {
            sync_handler.select_next_some().await;
        }
    });

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
            SwarmEvent::Behaviour(event) => println!("{:?}", event),
            SwarmEvent::ConnectionEstablished { peer_id, .. } => println!("New conn {:?}", peer_id),
            _ => {}
        }
    }
}
