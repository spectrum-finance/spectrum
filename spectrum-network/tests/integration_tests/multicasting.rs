use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;
use std::task::{Context, Poll};
use std::time::Duration;

use either::Either;
use futures::channel::mpsc::Sender;
use futures::channel::{mpsc, oneshot};
use futures::future::AbortHandle;
use futures::StreamExt;
use itertools::Itertools;
use k256::SecretKey;
use libp2p::{identity, Multiaddr};
use libp2p_identity::PeerId;
use rand::rngs::OsRng;

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::VerifiableAgainst;
use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig};
use spectrum_network::protocol::{
    OneShotProtocolConfig, OneShotProtocolSpec, ProtocolConfig, SIGMA_AGGR_PROTOCOL_ID,
};
use spectrum_network::protocol_handler::handel::Weighted;
use spectrum_network::protocol_handler::multicasting::overlay::DagOverlay;
use spectrum_network::protocol_handler::multicasting::{DagMulticasting, Multicasting};
use spectrum_network::protocol_handler::versioning::Versioned;
use spectrum_network::protocol_handler::void::VoidMessage;
use spectrum_network::protocol_handler::{
    ProtocolBehaviour, ProtocolBehaviourOut, ProtocolHandler, ProtocolSpec,
};
use spectrum_network::types::{ProtocolVer, Reputation};

use crate::integration_tests::aggregation::{create_swarm, k256_to_libsecp256k1};

struct McastTask<S> {
    process: Box<dyn Multicasting<S> + Send>,
    on_response: oneshot::Sender<S>,
}

pub struct SetTask<S> {
    pub initial_statement: Option<S>,
    pub on_response: oneshot::Sender<S>,
    pub overlay: DagOverlay,
}

pub struct MulticastingBehaviour<S> {
    host_ix: usize,
    state: Option<McastTask<S>>,
    inbox: mpsc::Receiver<SetTask<S>>,
    stash: HashMap<PeerId, S>,
}

trait AssertKinds: ProtocolBehaviour + Unpin {}
impl<S> AssertKinds for MulticastingBehaviour<S> where
    S: VerifiableAgainst<()>
        + CommutativePartialSemigroup
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Weighted
        + Versioned
        + Debug
        + Send
        + Clone
        + 'static
        + Unpin
{
}

impl<S> MulticastingBehaviour<S> {
    pub fn new(host_ix: usize) -> (Self, mpsc::Sender<SetTask<S>>) {
        let (snd, recv) = mpsc::channel(128);
        (
            Self {
                host_ix,
                state: None,
                inbox: recv,
                stash: HashMap::new(),
            },
            snd,
        )
    }
}

impl<S> ProtocolBehaviour for MulticastingBehaviour<S>
where
    S: VerifiableAgainst<()>
        + CommutativePartialSemigroup
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Weighted
        + Versioned
        + Debug
        + Send
        + Clone
        + 'static,
{
    type TProto = McastSpec<S>;

    fn inject_message(&mut self, peer_id: PeerId, content: <Self::TProto as ProtocolSpec>::TMessage) {
        match &mut self.state {
            None => {
                println!(
                    "[Peer-{}] :: Got message {:?} in Idle state",
                    self.host_ix, content
                );
                self.stash.insert(peer_id, content);
            }
            Some(McastTask {
                process: ref mut proc,
                ..
            }) => {
                println!("[Peer-{}] :: Got message {:?}", self.host_ix, content);
                proc.inject_message(peer_id, content);
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Option<ProtocolBehaviourOut<VoidMessage, S>>> {
        loop {
            match self.inbox.poll_next_unpin(cx) {
                Poll::Ready(Some(SetTask {
                    initial_statement,
                    on_response,
                    overlay,
                })) => {
                    println!("[Peer-{}] :: State=Idle=>Busy", self.host_ix);
                    println!("[Peer-{}] :: Stash.len={}", self.host_ix, self.stash.len());
                    let stash = mem::replace(&mut self.stash, HashMap::new());
                    for (p, s) in stash {
                        println!("[Peer-{}] :: Injecting stashed mesages", self.host_ix);
                        self.inject_message(p, s)
                    }
                    self.state = Some(McastTask {
                        process: Box::new(DagMulticasting::new(initial_statement, (), overlay)),
                        on_response,
                    })
                }
                Poll::Pending | Poll::Ready(None) => {}
            }
            match self.state.take() {
                None => {
                    println!("[Peer-{}] :: State=Idle", self.host_ix);
                }
                Some(McastTask {
                    mut process,
                    on_response,
                }) => {
                    println!("[Peer-{}] :: State=Busy", self.host_ix);
                    match process.poll(cx) {
                        Poll::Ready(out) => match out {
                            Either::Left(cmd) => {
                                self.state = Some(McastTask { process, on_response });
                                return Poll::Ready(Some(cmd));
                            }
                            Either::Right(res) => {
                                println!("[Peer-{}] :: Done", self.host_ix);
                                on_response.send(res).expect("Failed to complete response");
                                continue;
                            }
                        },
                        Poll::Pending => {
                            println!("[Peer-{}] :: Process=>Pending", self.host_ix);
                            self.state = Some(McastTask { process, on_response });
                        }
                    }
                }
            }
            return Poll::Pending;
        }
    }
}

pub struct McastSpec<S>(PhantomData<S>);

impl<S> ProtocolSpec for McastSpec<S>
where
    S: serde::Serialize + for<'de> serde::Deserialize<'de> + Versioned + Debug + Send + Clone,
{
    type THandshake = VoidMessage;
    type TMessage = S;
}

pub struct Peer<S> {
    pub peer_id: PeerId,
    pub peer_addr: Multiaddr,
    pub peer_pk: k256::PublicKey,
    pub peer_handle: AbortHandle,
    pub aggr_handler_mailbox: Sender<SetTask<S>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Statements<S>(pub Vec<S>);

impl<S: Clone + Eq> CommutativePartialSemigroup for Statements<S> {
    fn try_combine(&self, Statements(xs): &Self) -> Option<Self> {
        Some(Statements(
            self.0.clone().into_iter().chain(xs.clone()).dedup().collect(),
        ))
    }
}

impl<S> Weighted for Statements<S> {
    fn weight(&self) -> usize {
        self.0.len()
    }
}

impl<S> VerifiableAgainst<()> for Statements<S> {
    fn verify(&self, _: &()) -> bool {
        true
    }
}

impl<S> Versioned for Statements<S> {
    fn version(&self) -> ProtocolVer {
        ProtocolVer::default()
    }
}

pub fn setup_nodes<S>(n: usize) -> Vec<Peer<S>>
where
    S: VerifiableAgainst<()>
        + CommutativePartialSemigroup
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + Weighted
        + Versioned
        + Debug
        + Send
        + Clone
        + Unpin
        + 'static,
{
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
        let libp2p_pk = libp2p_identity::secp256k1::PublicKey::try_from_bytes(k256_encoded).unwrap();
        let peer_id = PeerId::from_public_key(&libp2p_identity::PublicKey::from(libp2p_pk));
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
        let (mcast, handler_snd) = MulticastingBehaviour::<S>::new(node_ix);
        let peer_state = PeerRepo::new(netw_config, vec![]);
        let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
        let (requests_snd, requests_recv) = mpsc::channel::<NetworkControllerIn>(100);
        let network_api = NetworkMailbox {
            mailbox_snd: requests_snd,
        };
        let (mut aggr_handler, aggr_mailbox) =
            ProtocolHandler::new(mcast, network_api, SIGMA_AGGR_PROTOCOL_ID, 10);
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
            println!("[Peer-{}] :: spawning protocol handler..", node_ix);
            loop {
                aggr_handler.select_next_some().await;
            }
        });
        tokio::task::spawn(async move {
            println!("[Peer-{}] :: spawning peer..", node_ix);
            abortable_peer.await
        });
        Peer {
            peer_id,
            peer_addr,
            peer_pk: peer_sk.public_key(),
            peer_handle: handle,
            aggr_handler_mailbox: handler_snd,
        }
    };
    let mut nodes = vec![];
    for i in 0..n {
        nodes.push(spawn_node(i));
    }
    nodes
}
