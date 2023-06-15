use std::collections::HashMap;
use std::error::Error;
use std::ops::Sub;
use std::str::FromStr;
use std::time::{Duration, Instant};

use async_std::fs::File;
use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::core::upgrade::Version;
use libp2p::identity::{self, Keypair};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{noise, tcp, yamux, Multiaddr};
use libp2p::{PeerId, Transport};

use log::{error, info};
use serde::{Deserialize, Serialize};
use spectrum_crypto::digest::{blake2b256_hash, Blake2b};
use spectrum_crypto::pubkey::PublicKey;
use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::data::PeerDestination;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig, PeersMailbox};
use spectrum_network::protocol::{
    OneShotProtocolConfig, OneShotProtocolSpec, ProtocolConfig, StatefulProtocolConfig, StatefulProtocolSpec,
    DISCOVERY_PROTOCOL_ID, SIGMA_AGGR_PROTOCOL_ID,
};
use spectrum_network::protocol_api::ProtocolMailbox;
use spectrum_network::protocol_handler::aggregation::AggregationAction;
use spectrum_network::protocol_handler::discovery::message::DiscoverySpec;
use spectrum_network::protocol_handler::discovery::{DiscoveryBehaviour, NodeStatus};
use spectrum_network::protocol_handler::handel::partitioning::{
    MakeBinomialPeerPartitions, PseudoRandomGenPerm,
};
use spectrum_network::protocol_handler::handel::{HandelConfig, Threshold};
use spectrum_network::protocol_handler::sigma_aggregation::SigmaAggregation;
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::{ProtocolVer, Reputation};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    log4rs::init_file("conf/log4rs.yaml", Default::default()).unwrap();

    run_sigma_aggregation().await;
    Ok(())
}

async fn run_sync_protocol() -> Result<(), Box<dyn Error>> {
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
        peer_manager_msg_buffer_size: 10,
    };
    let peer_state = PeerRepo::new(netw_config, boot_peers);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let sync_conf = StatefulProtocolConfig {
        supported_versions: vec![(
            DiscoverySpec::v1(),
            StatefulProtocolSpec {
                max_message_size: 100,
                approve_required: true,
            },
        )],
    };

    let local_status = NodeStatus {
        supported_protocols: Vec::from([DISCOVERY_PROTOCOL_ID]),
        height: 0,
    };
    let sync_behaviour = DiscoveryBehaviour::new(peers.clone(), local_status);
    const NC_MSG_BUFFER_SIZE: usize = 10;
    let (requests_snd, requests_recv) = mpsc::channel::<NetworkControllerIn>(NC_MSG_BUFFER_SIZE);
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };
    const PH_MSG_BUFFER_SIZE: usize = 10;
    let (mut sync_handler, sync_mailbox) = ProtocolHandler::new(
        sync_behaviour,
        network_api,
        DISCOVERY_PROTOCOL_ID,
        PH_MSG_BUFFER_SIZE,
    );
    let nc = NetworkController::new(
        peer_conn_handler_conf,
        HashMap::from([(
            DISCOVERY_PROTOCOL_ID,
            (ProtocolConfig::Stateful(sync_conf), sync_mailbox),
        )]),
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

async fn run_sigma_aggregation() {
    let one_shot_proto_conf = OneShotProtocolConfig {
        version: ProtocolVer::default(),
        spec: OneShotProtocolSpec {
            max_message_size: 5000,
        },
    };
    let peer_conn_handler_conf = PeerConnHandlerConf {
        async_msg_buffer_size: 100,
        sync_msg_buffer_size: 100,
        open_timeout: Duration::from_secs(60),
        initial_keep_alive: Duration::from_secs(120),
    };
    let netw_config = NetworkingConfig {
        min_known_peers: 1,
        min_outbound: 1,
        max_inbound: 10,
        max_outbound: 20,
    };
    let peer_manager_conf = PeerManagerConfig {
        min_acceptable_reputation: Reputation::from(-50),
        min_reputation: Reputation::from(-20),
        conn_reset_outbound_backoff: Duration::from_secs(120),
        conn_alloc_interval: Duration::from_secs(30),
        prot_alloc_interval: Duration::from_secs(30),
        protocols_allocation: Vec::new(),
        peer_manager_msg_buffer_size: 1000,
    };
    let handel_conf = HandelConfig {
        threshold: Threshold { num: 8, denom: 8 },
        window_shrinking_factor: 4,
        initial_scoring_window: 3,
        fast_path_window: 10,
        dissemination_interval: Duration::from_millis(100),
        level_activation_delay: Duration::from_millis(50),
        poll_fn_delay: Duration::from_millis(5),
    };

    let mut file = File::open("conf/peer_info.yml").await.unwrap();
    let mut yaml_string = String::new();
    file.read_to_string(&mut yaml_string).await.unwrap();

    let PeerInfo {
        peer_id,
        peer_addr,
        peer_sk_base_16,
        committee,
    } = serde_yaml::from_str(&yaml_string).unwrap();

    let peer_sk_bytes = base16::decode(&peer_sk_base_16).unwrap();
    let peer_sk = k256::SecretKey::from_slice(&peer_sk_bytes).unwrap();

    let peer_key = identity::Keypair::from(identity::secp256k1::Keypair::from(k256_to_libsecp256k1(
        peer_sk.clone(),
    )));

    let seed = [0_u8; 32];
    let gen_perm = PseudoRandomGenPerm::new(seed);

    let (mut aggr_handler_snd, aggr_handler_inbox) = mpsc::channel::<AggregationAction<Blake2b>>(100);
    let sig_aggr = SigmaAggregation::new(
        peer_sk,
        handel_conf,
        MakeBinomialPeerPartitions { rng: gen_perm },
        aggr_handler_inbox,
    );
    let peer_state = PeerRepo::new(netw_config, vec![]);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let (requests_snd, requests_recv) = mpsc::channel::<NetworkControllerIn>(100);
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };
    let (mut aggr_handler, aggr_mailbox) =
        ProtocolHandler::new(sig_aggr, network_api, SIGMA_AGGR_PROTOCOL_ID, 100);
    let nc = NetworkController::new(
        peer_conn_handler_conf,
        HashMap::from([(
            SIGMA_AGGR_PROTOCOL_ID,
            (ProtocolConfig::OneShot(one_shot_proto_conf.clone()), aggr_mailbox),
        )]),
        peers,
        peer_manager,
        requests_recv,
    );
    tokio::task::spawn(async move {
        info!("spawning protocol handler");
        loop {
            aggr_handler.select_next_some().await;
        }
    });

    let md = blake2b256_hash(b"foo");
    let (snd, recv) = futures::channel::oneshot::channel();

    aggr_handler_snd
        .send(AggregationAction::Reset {
            new_committee: committee.clone(),
            new_message: md,
            channel: snd,
        })
        .await
        .unwrap();

    let started_at = Instant::now();
    async_std::task::spawn(async move {
        let res = recv.await;
        let finished_at = Instant::now();
        let elapsed = finished_at.sub(started_at);
        match res {
            Ok(_) => info!("Finished aggr in {} millis", elapsed.as_millis()),
            Err(_) => error!("Failed aggr in {} millis", elapsed.as_millis()),
        }
    });

    info!("spawning peer");
    create_swarm(peer_key.clone(), nc).await
}

pub async fn create_swarm(
    local_key: Keypair,
    nc: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>,
) {
    let transport = tcp::async_io::Transport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key).unwrap()) // todo: avoid auth
        .multiplex(yamux::Config::default())
        .boxed();
    let local_peer_id = PeerId::from(local_key.public());
    let mut swarm = SwarmBuilder::with_async_std_executor(transport, nc, local_peer_id).build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/8000".parse().unwrap()).unwrap();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => info!("Listening on {:?}", address),
            ce => {}
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_sk_base_16: String,
    pub committee: HashMap<PublicKey, Option<Multiaddr>>,
}

pub fn k256_to_libsecp256k1(secret_key: k256::SecretKey) -> identity::secp256k1::SecretKey {
    identity::secp256k1::SecretKey::try_from_bytes(secret_key.to_bytes().as_mut_slice()).unwrap()
}
