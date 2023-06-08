use std::collections::HashMap;
use std::time::Duration;

use elliptic_curve::rand_core::OsRng;
use futures::channel::mpsc;
use futures::channel::mpsc::Sender;
use futures::future::AbortHandle;
use futures::StreamExt;
use k256::SecretKey;
use libp2p::core::upgrade::Version;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, Transport};
use libp2p_identity::{Keypair, PeerId};
use log::trace;
use std::io::Write;

use serde::{Deserialize, Serialize};
use spectrum_crypto::digest::Blake2b;
use spectrum_crypto::pubkey::PublicKey;
use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig, PeersMailbox};
use spectrum_network::protocol::{
    OneShotProtocolConfig, OneShotProtocolSpec, ProtocolConfig, SIGMA_AGGR_PROTOCOL_ID,
};
use spectrum_network::protocol_api::ProtocolMailbox;
use spectrum_network::protocol_handler::aggregation::AggregationAction;
use spectrum_network::protocol_handler::handel::partitioning::{
    MakeBinomialPeerPartitions, PseudoRandomGenPerm,
};
use spectrum_network::protocol_handler::handel::{HandelConfig, Threshold};
use spectrum_network::protocol_handler::sigma_aggregation::{SigmaAggregation};
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::{ProtocolVer, Reputation};

pub struct Peer {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_pk: k256::PublicKey,
    pub peer_handle: AbortHandle,
    pub aggr_handler_mailbox: Sender<AggregationAction<Blake2b>>,
}

pub fn k256_to_libsecp256k1(secret_key: SecretKey) -> identity::secp256k1::SecretKey {
    identity::secp256k1::SecretKey::try_from_bytes(secret_key.to_bytes().as_mut_slice()).unwrap()
}

pub fn setup_nodes(n: usize) -> Vec<Peer> {
    let mut rng = OsRng;
    let mut spawn_node = move |node_ix| {
        let peer_sk = SecretKey::random(&mut rng);
        let peer_key = identity::Keypair::from(identity::secp256k1::Keypair::from(k256_to_libsecp256k1(
            peer_sk.clone(),
        )));
        use elliptic_curve::sec1::ToEncodedPoint;
        let k256_pk = peer_sk.public_key();
        let k256_point = k256_pk.to_encoded_point(true);
        let k256_encoded = k256_point.as_bytes();
        let libp2p_pk = libp2p_identity::secp256k1::PublicKey::decode(k256_encoded).unwrap();
        let peer_id = PeerId::from_public_key(&libp2p_identity::PublicKey::Secp256k1(libp2p_pk));
        let other_peer_id = PeerId::from(peer_key.public());
        assert_eq!(peer_id, other_peer_id);
        let peer_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", 8000 + node_ix).parse().unwrap();

        let bb = peer_sk.to_bytes().to_vec();
        let key = SecretKey::from_slice(&bb).unwrap();
        assert_eq!(key, peer_sk);

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
            dissemination_interval: Duration::from_millis(40),
            level_activation_delay: Duration::from_millis(50),
            poll_fn_delay: Duration::from_millis(5),
        };
        let seed = [0_u8; 32];
        let gen_perm = PseudoRandomGenPerm::new(seed);
        let (aggr_handler_snd, aggr_handler_inbox) = mpsc::channel::<AggregationAction<Blake2b>>(100);
        let sig_aggr = SigmaAggregation::new(
            peer_sk.clone(),
            handel_conf,
            MakeBinomialPeerPartitions {
                rng: gen_perm.clone(),
            },
            aggr_handler_inbox,
        );
        let peer_state = PeerRepo::new(netw_config, vec![]);
        let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
        let (requests_snd, requests_recv) = mpsc::channel::<NetworkControllerIn>(100);
        let network_api = NetworkMailbox {
            mailbox_snd: requests_snd,
        };
        let (mut aggr_handler, aggr_mailbox) = ProtocolHandler::new(sig_aggr, network_api, SIGMA_AGGR_PROTOCOL_ID, 10);
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
        let (abortable_peer, handle) =
            futures::future::abortable(create_swarm(peer_key.clone(), nc, peer_addr.clone(), node_ix));
        tokio::task::spawn(async move {
            println!("PEER:{} :: spawning protocol handler..", node_ix);
            loop {
                aggr_handler.select_next_some().await;
            }
        });
        tokio::task::spawn(async move {
            println!("PEER:{} :: spawning peer..", node_ix);
            abortable_peer.await
        });
        Peer {
            peer_id,
            peer_addr,
            peer_pk: peer_sk.public_key(),
            peer_handle: handle,
            aggr_handler_mailbox: aggr_handler_snd,
        }
    };
    let mut nodes = vec![];
    for i in 0..n {
        nodes.push(spawn_node(i));
    }
    nodes
}

pub async fn create_swarm(
    local_key: Keypair,
    nc: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>,
    addr: Multiaddr,
    peer_index: usize,
) {
    let transport = tcp::async_io::Transport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key).unwrap()) // todo: avoid auth
        .multiplex(yamux::Config::default())
        .boxed();
    let local_peer_id = PeerId::from(local_key.public());
    let mut swarm = SwarmBuilder::with_async_std_executor(transport, nc, local_peer_id).build();

    swarm.listen_on(addr).unwrap();

    let peer = format!("Peer::{}", peer_index);
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("{} :: Listening on {:?}", peer, address),
            ce => {
                trace!("{} :: Recv event :: {:?}", peer, ce);
            }
        }
    }
}

/// Serialise this into YAML file for Docker testing.
#[derive(Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_sk_base_16: String,
    pub committee: HashMap<PublicKey, Option<Multiaddr>>,
}

pub struct IndividualPeerInfo {
    peer_id: PeerId,
    peer_addr: Multiaddr,
    peer_sk_base_16: String,
}

/// Used for Docker testing.
fn generate_peer_info_files(num_nodes: usize) {
    let mut rng = OsRng;
    let mut committee = HashMap::default();
    let mut individual_peer_info = vec![];
    for node_ix in 0..num_nodes {
        let peer_sk = SecretKey::random(&mut rng);
        let peer_key = identity::Keypair::from(identity::secp256k1::Keypair::from(k256_to_libsecp256k1(
            peer_sk.clone(),
        )));
        let peer_id = PeerId::from(peer_key.public());
        let peer_addr: Multiaddr = format!("/ip4/172.18.12.{}/tcp/8000", node_ix).parse().unwrap();

        committee.insert(peer_sk.public_key().into(), Some(peer_addr.clone()));
        let peer_info = IndividualPeerInfo {
            peer_id,
            peer_addr,
            peer_sk_base_16: base16::encode_lower(&peer_sk.to_bytes().to_vec()),
        };
        individual_peer_info.push(peer_info);
    }

    for (node_ix, info) in individual_peer_info.into_iter().enumerate() {
        let peer_info = PeerInfo {
            peer_id: info.peer_id,
            peer_addr: info.peer_addr,
            peer_sk_base_16: info.peer_sk_base_16,
            committee: committee.clone(),
        };
        let yaml_string = serde_yaml::to_string(&peer_info).unwrap();
        let mut file = std::fs::File::create(format!("peer_input_{}.yml", node_ix)).unwrap();
        file.write_all(yaml_string.as_bytes()).unwrap();

        // Flush the contents to ensure all data is written
        file.flush().unwrap();
    }
}
