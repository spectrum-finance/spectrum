use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::ops::Sub;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, StreamExt};
use k256::SecretKey;
use libp2p::core::upgrade::Version;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::{identity, Multiaddr, PeerId, Transport};
use rand::rngs::OsRng;
use rand::Rng;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use spectrum_crypto::digest::{blake2b256_hash, Blake2b256, Blake2bDigest256};
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
use tokio::time::sleep;
use tracing::{debug, trace};

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();
    let command = Command::from(args.command);
    match command {
        Command::RunNode(config) => {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber).unwrap();
            let addr = SocketAddr::from((
                config.public_info.network_info.ip_address,
                config.public_info.network_info.rest_api_port,
            ));
            let app: Router<(), _> = Router::new()
                .route("/aggregate", post(aggregate))
                .with_state(config);

            tracing::debug!("listening on {}", addr);
            axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
        }
        Command::GenerateNewCommittee(form_new_committee) => {
            let mut members = vec![];
            for (node_ix, network_info) in form_new_committee.members {
                let pub_key = generate_node_config_files(node_ix, &network_info);
                members.push((node_ix, pub_key, network_info));
            }
            let committee = Committee { members };
            let yaml_string = serde_yaml::to_string(&committee).unwrap();
            let mut file = std::fs::File::create("committee.yaml").unwrap();
            file.write_all(yaml_string.as_bytes()).unwrap();
            file.flush().unwrap();
        }
        Command::OrchestrateAggregation(orchestrate_aggr, committee) => {
            orchestrate_aggregation(orchestrate_aggr, committee).await;
        }
        Command::GenerateOrchestrationTemplate(proto) => {
            let yaml_string = serde_yaml::to_string(&proto).unwrap();
            let mut file = std::fs::File::create("orchestrate_template.yaml").unwrap();
            file.write_all(yaml_string.as_bytes()).unwrap();
            file.flush().unwrap();
        }
    }
}

async fn aggregate(
    State(config): State<NodeConfig>,
    Json(request): Json<SigmaAggregationRequest>,
) -> StatusCode {
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
    let (mut aggr_handler_snd, aggr_handler_inbox) = mpsc::channel::<AggregationAction<Blake2b256>>(100);
    let overlay_builder = RedundancyDagOverlayBuilder {
        redundancy_factor: multicasting_conf.redundancy_factor,
        seed: multicasting_conf.seed,
    };
    let gen_perm = PseudoRandomGenPerm::new(request.public_seed);
    let peer_sk_bytes = base16::decode(&config.peer_sk_base_16).unwrap();
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
                Blake2b256,
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

    let mut peer_addr = Multiaddr::from(config.public_info.network_info.ip_address);
    peer_addr.push(libp2p::multiaddr::Protocol::Tcp(
        config.public_info.network_info.peer_port,
    ));

    let (abortable_peer, abort_handle) =
        futures::future::abortable(create_swarm(peer_key.clone(), nc, peer_addr));

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

async fn orchestrate_aggregation(orchestrate_aggr: OrchestrateAggregation, committee: Committee) {
    let committee_for_request: HashMap<PublicKey, Option<Multiaddr>> = committee
        .members
        .iter()
        .map(|(_, pub_key, network_info)| {
            let mut peer_addr = Multiaddr::from(network_info.ip_address);
            peer_addr.push(libp2p::multiaddr::Protocol::Tcp(network_info.peer_port));
            (pub_key.clone(), Some(peer_addr))
        })
        .collect();

    let request = SigmaAggregationRequest {
        message: orchestrate_aggr.message,
        committee: committee_for_request,
        public_seed: orchestrate_aggr.public_seed,
        threshold: orchestrate_aggr.threshold,
    };

    let mut join_handles = vec![];

    for (node_ix, _, network_info) in committee.members {
        let ip_addr_str = network_info.ip_address.to_string();
        let url = Url::parse(&format!(
            "http://{}:{}/aggregate",
            ip_addr_str, network_info.rest_api_port
        ))
        .expect("Invalid URL");
        let request = request.clone();
        let handicapped_nodes = orchestrate_aggr.handicapped_nodes.clone();
        if let Some((_, ref handicap)) = handicapped_nodes.into_iter().find(|(n_ix, _)| node_ix == *n_ix) {
            match handicap {
                NodeHandicap::Delay(delay) => {
                    let delay = *delay;
                    let handle = tokio::spawn(async move {
                        sleep(delay).await;
                        reqwest::Client::new()
                            .post(url)
                            .json(&request)
                            .send()
                            .await
                            .unwrap();
                    });
                    join_handles.push(handle);
                }
                NodeHandicap::Byzantine => (),
            }
        } else {
            let handle = tokio::spawn(async move {
                reqwest::Client::new()
                    .post(url)
                    .json(&request)
                    .send()
                    .await
                    .unwrap();
            });
            join_handles.push(handle);
        }
    }
    let _ = futures::future::join_all(join_handles).await;
}

fn k256_to_libsecp256k1(secret_key: k256::SecretKey) -> libp2p::identity::secp256k1::SecretKey {
    libp2p::identity::secp256k1::SecretKey::try_from_bytes(secret_key.to_bytes().as_mut_slice()).unwrap()
}

async fn create_swarm(
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeConfig {
    public_info: PublicNodeInfo,
    peer_sk_base_16: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublicNodeInfo {
    peer_id: PeerId,
    network_info: NodeNetworkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeNetworkInfo {
    ip_address: IpAddr,
    /// Port used for REST API.
    rest_api_port: u16,
    /// Port used by node for sigma-aggregation
    peer_port: u16,
}

#[derive(Serialize, Deserialize, Clone)]
struct SigmaAggregationRequest {
    message: Blake2bDigest256,
    committee: HashMap<PublicKey, Option<Multiaddr>>,
    public_seed: [u8; 32],
    threshold: Threshold,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct NodeIx(usize);

#[derive(Clone, Debug)]
enum NodeHandicap {
    Delay(Duration),
    Byzantine,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DelayedNode {
    node_ix: NodeIx,
    delay_in_milliseconds: u64,
}

#[derive(Clone, Debug)]
struct OrchestrateAggregation {
    message: Blake2bDigest256,
    public_seed: [u8; 32],
    threshold: Threshold,
    handicapped_nodes: Vec<(NodeIx, NodeHandicap)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OrchestrateAggregationProto {
    message: Blake2bDigest256,
    public_seed: [u8; 32],
    threshold: Threshold,
    delayed_nodes: Vec<DelayedNode>,
    byzantine_nodes: Vec<NodeIx>,
}

impl From<OrchestrateAggregationProto> for OrchestrateAggregation {
    fn from(value: OrchestrateAggregationProto) -> Self {
        let mut handicapped_nodes = vec![];
        for DelayedNode {
            node_ix,
            delay_in_milliseconds,
        } in value.delayed_nodes
        {
            handicapped_nodes.push((
                node_ix,
                NodeHandicap::Delay(Duration::from_millis(delay_in_milliseconds)),
            ));
        }

        for node_ix in value.byzantine_nodes {
            handicapped_nodes.push((node_ix, NodeHandicap::Byzantine));
        }

        OrchestrateAggregation {
            message: value.message,
            public_seed: value.public_seed,
            threshold: value.threshold,
            handicapped_nodes,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FormNewCommittee {
    members: Vec<(NodeIx, NodeNetworkInfo)>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Committee {
    members: Vec<(NodeIx, PublicKey, NodeNetworkInfo)>,
}

#[derive(Parser)]
struct AppArgs {
    #[clap(subcommand)]
    command: CLICommand,
}

#[derive(Clone, Debug, Subcommand)]
enum CLICommand {
    RunNode {
        #[arg(long, short)]
        config_path: String,
    },
    GenerateNewCommittee {
        #[arg(long, short)]
        config_path: String,
    },
    OrchestrateAggregation {
        #[arg(long, short)]
        orchestration_path: String,
        #[arg(long, short)]
        committee_data_path: String,
    },
    GenerateOrchestrationTemplate {
        #[arg(long, short)]
        message: String,
        #[arg(long)]
        threshold_numerator: usize,
        #[arg(long)]
        threshold_denominator: usize,
    },
}

#[derive(Clone, Debug)]
enum Command {
    RunNode(NodeConfig),
    GenerateNewCommittee(FormNewCommittee),
    OrchestrateAggregation(OrchestrateAggregation, Committee),
    GenerateOrchestrationTemplate(OrchestrateAggregationProto),
}

impl From<CLICommand> for Command {
    fn from(value: CLICommand) -> Self {
        match value {
            CLICommand::RunNode { config_path } => {
                let data = std::fs::read_to_string(config_path.clone())
                    .unwrap_or_else(|_| panic!("{} doesn't exist!", config_path));
                let config: NodeConfig = serde_yaml::from_str(&data)
                    .unwrap_or_else(|_| panic!("couldn't deserialize into NodeConfig!"));
                Command::RunNode(config)
            }
            CLICommand::GenerateNewCommittee { config_path } => {
                let data = std::fs::read_to_string(config_path.clone())
                    .unwrap_or_else(|_| panic!("{} doesn't exist!", config_path));
                let new_committee: FormNewCommittee = serde_yaml::from_str(&data)
                    .unwrap_or_else(|_| panic!("couldn't deserialize into NewCommittee!"));
                Command::GenerateNewCommittee(new_committee)
            }
            CLICommand::OrchestrateAggregation {
                orchestration_path,
                committee_data_path,
            } => {
                let orchestration_data = std::fs::read_to_string(orchestration_path.clone())
                    .unwrap_or_else(|e| panic!("Can't read {}: {:?}!", orchestration_path, e));
                let committee_data = std::fs::read_to_string(committee_data_path.clone())
                    .unwrap_or_else(|e| panic!("Can't read {}: {:?}!", committee_data_path, e));

                let orchestrate_aggr_proto: OrchestrateAggregationProto =
                    serde_yaml::from_str(&orchestration_data)
                        .unwrap_or_else(|_| panic!("couldn't deserialize into HandicappedNodes!"));
                let orchestrate_aggr = OrchestrateAggregation::from(orchestrate_aggr_proto);
                let committee: Committee = serde_yaml::from_str(&committee_data)
                    .unwrap_or_else(|_| panic!("couldn't deserialize into Committee!"));
                Command::OrchestrateAggregation(orchestrate_aggr, committee)
            }
            CLICommand::GenerateOrchestrationTemplate {
                message,
                threshold_numerator,
                threshold_denominator,
            } => {
                let mut rng = rand::thread_rng();
                let mut public_seed = [0_u8; 32];
                rng.fill(&mut public_seed);
                let message = blake2b256_hash(message.as_bytes());
                let proto = OrchestrateAggregationProto {
                    message,
                    public_seed,
                    threshold: Threshold {
                        num: threshold_numerator,
                        denom: threshold_denominator,
                    },
                    delayed_nodes: vec![],
                    byzantine_nodes: vec![],
                };
                Command::GenerateOrchestrationTemplate(proto)
            }
        }
    }
}

fn generate_node_config_files(NodeIx(node_ix): NodeIx, network_info: &NodeNetworkInfo) -> PublicKey {
    let mut rng = OsRng;
    let peer_sk = SecretKey::random(&mut rng);
    let pub_key = peer_sk.public_key();
    let peer_key = libp2p::identity::Keypair::from(identity::secp256k1::Keypair::from(k256_to_libsecp256k1(
        peer_sk.clone(),
    )));
    let peer_id = PeerId::from(peer_key.public());
    let mut peer_addr = Multiaddr::from(network_info.ip_address);
    peer_addr.push(libp2p::multiaddr::Protocol::Tcp(network_info.peer_port));

    let node_config = NodeConfig {
        public_info: PublicNodeInfo {
            peer_id,
            network_info: network_info.clone(),
        },
        peer_sk_base_16: base16::encode_lower(&peer_sk.to_bytes().to_vec()),
    };

    let yaml_string = serde_yaml::to_string(&node_config).unwrap();
    let mut file = std::fs::File::create(format!("node_config_{}.yml", node_ix)).unwrap();
    file.write_all(yaml_string.as_bytes()).unwrap();

    // Flush the contents to ensure all data is written
    file.flush().unwrap();
    pub_key.into()
}
