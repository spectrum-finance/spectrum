use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Sub;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use libp2p::core::upgrade::Version;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Transport};
use serde::{Deserialize, Serialize};
use spectrum_crypto::digest::{Blake2b, Blake2bDigest256};
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
use spectrum_network::protocol_handler::multicasting::overlay::RedundancyDagOverlayBuilder;
use spectrum_network::protocol_handler::multicasting::DagMulticastingConfig;
use spectrum_network::protocol_handler::sigma_aggregation::SigmaAggregation;
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::{ProtocolVer, Reputation};
use tracing::{debug, trace};

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let args = Args::parse();

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port_to_listen_on));
    let app: Router<(), _> = Router::new()
        //.route("/", get(root))
        .route("/aggregate", post(aggregate))
        .with_state(args);

    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn aggregate(State(args): State<Args>, Json(request): Json<SigmaAggregationRequest>) -> StatusCode {
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
        threshold: request.threshold,
        window_shrinking_factor: 4,
        initial_scoring_window: 3,
        fast_path_window: 16,
        dissemination_delay: Duration::from_millis(40),
        level_activation_delay: Duration::from_millis(50),
        throttle_factor: 5,
    };
    let multicasting_conf = DagMulticastingConfig {
        processing_delay: Duration::from_millis(10),
        multicasting_duration: Duration::from_millis(200),
        redundancy_factor: 5,
        seed: 42,
    };
    let (mut aggr_handler_snd, aggr_handler_inbox) = mpsc::channel::<AggregationAction<Blake2b>>(100);
    let overlay_builder = RedundancyDagOverlayBuilder {
        redundancy_factor: multicasting_conf.redundancy_factor,
        seed: multicasting_conf.seed,
    };
    let gen_perm = PseudoRandomGenPerm::new(request.public_seed);
    let peer_sk_bytes = base16::decode(&args.peer_sk_base_16).unwrap();
    let peer_sk = k256::SecretKey::from_slice(&peer_sk_bytes).unwrap();
    let sig_aggr = SigmaAggregation::new(
        peer_sk.clone(),
        handel_conf,
        multicasting_conf,
        MakeBinomialPeerPartitions {
            rng: gen_perm.clone(),
        },
        overlay_builder,
        aggr_handler_inbox,
    );
    let peer_state = PeerRepo::new(netw_config, vec![]);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let (requests_snd, requests_recv) = mpsc::channel::<NetworkControllerIn>(100);
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };

    let (mut aggr_handler, aggr_mailbox): (
        ProtocolHandler<
            SigmaAggregation<
                Blake2b,
                MakeBinomialPeerPartitions<PseudoRandomGenPerm>,
                RedundancyDagOverlayBuilder,
            >,
            NetworkMailbox,
        >,
        _,
    ) = ProtocolHandler::new(sig_aggr, network_api, SIGMA_AGGR_PROTOCOL_ID, 10);
    let nc: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox> = NetworkController::new(
        peer_conn_handler_conf,
        HashMap::from([(
            SIGMA_AGGR_PROTOCOL_ID,
            (ProtocolConfig::OneShot(one_shot_proto_conf), aggr_mailbox),
        )]),
        peers,
        peer_manager,
        requests_recv,
    );

    let peer_key = libp2p::identity::Keypair::from(libp2p::identity::secp256k1::Keypair::from(
        k256_to_libsecp256k1(peer_sk.clone()),
    ));

    let (abortable_peer, abort_handle) =
        futures::future::abortable(create_swarm(peer_key.clone(), nc, args.peer_addr.clone()));

    //aggr_handler_mailboxes.push(peer.aggr_handler_mailbox);
    tokio::task::spawn(async move {
        trace!("Spawning protocol handler..");
        loop {
            aggr_handler.select_next_some().await;
        }
    });
    tokio::task::spawn(async move {
        trace!("Spawning peer..");
        abortable_peer.await
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let (snd, recv) = oneshot::channel();
    async_std::task::block_on(aggr_handler_snd.send(AggregationAction::Reset {
        new_committee: request.committee,
        new_message: request.message,
        channel: snd,
    }))
    .unwrap();

    let started_at = Instant::now();
    async_std::task::spawn(async move {
        let res = recv.await;
        let finished_at = Instant::now();
        let elapsed = finished_at.sub(started_at);
        match res {
            Ok(_) => {
                debug!("Finished aggr in {} millis", elapsed.as_millis())
            }
            Err(_) => debug!("Failed aggr in {} millis", elapsed.as_millis()),
        }
    });

    tokio::time::sleep(Duration::from_secs(10)).await;
    abort_handle.abort();

    StatusCode::OK
}

//async fn root(State(peer_sk_base_16): State<String>) -> &'static str {
//    "Send request to /aggregate"
//}

pub fn k256_to_libsecp256k1(secret_key: k256::SecretKey) -> libp2p::identity::secp256k1::SecretKey {
    libp2p::identity::secp256k1::SecretKey::try_from_bytes(secret_key.to_bytes().as_mut_slice()).unwrap()
}

pub async fn create_swarm(
    local_key: libp2p::identity::Keypair,
    nc: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>,
    addr: Multiaddr,
) {
    let transport = libp2p::tcp::async_io::Transport::default()
        .upgrade(Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(&local_key).unwrap()) // todo: avoid auth
        .multiplex(libp2p::yamux::Config::default())
        .boxed();
    let local_peer_id = PeerId::from(local_key.public());
    let mut swarm = SwarmBuilder::with_async_std_executor(transport, nc, local_peer_id).build();

    swarm.listen_on(addr).unwrap();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => debug!("Listening on {:?}", address),
            ce => {
                trace!("Recv event :: {:?}", ce);
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Parser)]
pub struct Args {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_sk_base_16: String,
    pub port_to_listen_on: u16,
}

#[derive(Serialize, Deserialize)]
pub struct SigmaAggregationRequest {
    pub message: Blake2bDigest256,
    pub committee: HashMap<PublicKey, Option<Multiaddr>>,
    pub public_seed: [u8; 32],
    pub threshold: Threshold,
}
