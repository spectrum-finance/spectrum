use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::future::Future;
use std::time::Duration;

use elliptic_curve::rand_core::OsRng;
use futures::channel::mpsc;
use futures::channel::mpsc::Sender;
use futures::future::AbortHandle;
use futures::StreamExt;
use k256::SecretKey;
use libp2p::core::transport::upgrade::Multiplexed;
use libp2p::core::upgrade::Version;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, Transport};
use libp2p_identity::{Keypair, PeerId};
use rand::Rng;

use spectrum_crypto::digest::Blake2b;
use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig, PeersMailbox};
use spectrum_network::protocol::{OneShotProtocolConfig, OneShotProtocolSpec, ProtocolConfig};
use spectrum_network::protocol_api::{ProtocolEvent, ProtocolMailbox};
use spectrum_network::protocol_handler::aggregation::AggregationAction;
use spectrum_network::protocol_handler::handel::partitioning::{
    MakeBinomialPeerPartitions, PseudoRandomGenPerm,
};
use spectrum_network::protocol_handler::handel::{HandelConfig, Threshold};
use spectrum_network::protocol_handler::sigma_aggregation::SigmaAggregation;
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::{ProtocolId, ProtocolVer, Reputation};

#[cfg_attr(feature = "test_peer_punish_too_slow", ignore)]
#[async_std::test]
async fn sigma_aggregation_normal() {}

pub struct Peer {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_key: Keypair,
    pub peer_handle: AbortHandle,
    pub aggr_handler_mailbox: Sender<AggregationAction<Blake2b>>,
}

fn k256_to_libsecp255k1(secret_key: SecretKey) -> identity::secp256k1::SecretKey {
    identity::secp256k1::SecretKey::from_bytes(secret_key.to_bytes().as_mut_slice()).unwrap()
}

pub fn setup_nodes(n: usize) -> Vec<Peer> {
    let mut rng = OsRng;
    let mut node_ix = 0usize;
    let setup_node = || {
        let peer_sk = SecretKey::random(&mut rng);
        let peer_key = identity::Keypair::from(identity::secp256k1::Keypair::from(k256_to_libsecp255k1(
            peer_sk.clone(),
        )));
        let peer_id = PeerId::from(peer_key.clone().public());
        let peer_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", node_ix).parse().unwrap();

        let pid = ProtocolId::from_u8(1u8);
        let ver = ProtocolVer::from(1u8);
        let one_shot_proto_conf = OneShotProtocolConfig {
            version: ver,
            spec: OneShotProtocolSpec {
                max_message_size: 500,
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
            threshold: Threshold { num: 2, denom: 4 },
            window_shrinking_factor: 4,
            initial_scoring_window: 3,
            fast_path_window: 10,
            dissemination_interval: Duration::from_millis(20),
            level_activation_delay: Duration::from_millis(50),
        };
        let seed = rng.gen::<[u8; 32]>();
        let gen_perm = PseudoRandomGenPerm::new(seed);
        let (aggr_handler_snd, aggr_handler_inbox) = mpsc::channel::<AggregationAction<Blake2b>>(100);
        let sig_aggr = SigmaAggregation::new(
            peer_sk,
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
        let (mut aggr_handler, aggr_mailbox) = ProtocolHandler::new(sig_aggr, network_api, 10);
        let nc = NetworkController::new(
            peer_conn_handler_conf,
            HashMap::from([(
                pid,
                (ProtocolConfig::OneShot(one_shot_proto_conf.clone()), aggr_mailbox),
            )]),
            peers,
            peer_manager,
            requests_recv,
        );
        let (abortable_peer, handle) = futures::future::abortable(create_swarm(
            peer_key.clone(),
            nc,
            peer_addr.clone(),
            &*format!("{}", node_ix),
        ));
        async_std::task::spawn(async move {
            println!("PEER:{} :: spawning protocol handler..", node_ix);
            loop {
                aggr_handler.select_next_some().await;
            }
        });
        async_std::task::spawn(async move {
            println!("PEER:{} :: spawning peer..", node_ix);
            abortable_peer.await
        });
        Peer {
            peer_id,
            peer_addr,
            peer_key,
            peer_handle: handle,
            aggr_handler_mailbox: aggr_handler_snd
        }
    };
    todo!()
}

pub async fn create_swarm(
    local_key: Keypair,
    nc: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>,
    addr: Multiaddr,
    peer_mnemonic: &str,
) {
    let transport = tcp::async_io::Transport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(noise::Config::new(&local_key).unwrap()) // todo: avoid auth
        .multiplex(yamux::Config::default())
        .boxed();
    let local_peer_id = PeerId::from(local_key.public());
    let mut swarm = SwarmBuilder::with_async_std_executor(transport, nc, local_peer_id).build();

    swarm.listen_on(addr).unwrap();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
            ce => {
                dbg!(peer_mnemonic, ce);
            }
        }
    }
}
