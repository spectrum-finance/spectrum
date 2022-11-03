mod peer_manager;

use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::identity::Keypair;
use libp2p::{
    core::{
        connection::ConnectionId,
        transport::{ListenerId, MemoryTransport},
        upgrade, ConnectedPoint,
    },
    identity, noise,
    swarm::{
        ConnectionHandler, DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
        PollParameters, Swarm,
    },
    yamux, Multiaddr, PeerId, Transport,
};
use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::PeerConnHandlerConf;
use spectrum_network::peer_manager::peer_index::PeerIndexConfig;
use spectrum_network::peer_manager::peers_state::PeersStateDef;
use spectrum_network::peer_manager::{PeerManager, PeerManagerConfig, PeersMailbox};
use spectrum_network::protocol::{ProtocolConfig, ProtocolSpec, SYNC_PROTOCOL_ID};
use spectrum_network::protocol_api::ProtocolMailbox;
use spectrum_network::protocol_handler::sync::message::SyncSpec;
use spectrum_network::protocol_handler::sync::{NodeStatus, SyncBehaviour};
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::Reputation;
use std::collections::HashMap;
use std::{
    error, io,
    task::{Context, Poll},
    time::Duration,
};

/// Wraps around the `CustomBehaviour` network behaviour, and adds hardcoded node addresses to it.
pub struct CustomProtoWithAddr {
    inner: NetworkController<PeersMailbox, PeerManager<PeersStateDef>, ProtocolMailbox>,
    addrs: Vec<(PeerId, Multiaddr)>,
}

impl std::ops::Deref for CustomProtoWithAddr {
    type Target = NetworkController<PeersMailbox, PeerManager<PeersStateDef>, ProtocolMailbox>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for CustomProtoWithAddr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl NetworkBehaviour for CustomProtoWithAddr {
    type ConnectionHandler = <NetworkController<PeersMailbox, PeerManager<PeersStateDef>, ProtocolMailbox> as NetworkBehaviour>::ConnectionHandler;
    type OutEvent = <NetworkController<PeersMailbox, PeerManager<PeersStateDef>, ProtocolMailbox> as NetworkBehaviour>::OutEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        self.inner.new_handler()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let mut list = self.inner.addresses_of_peer(peer_id);
        for (p, a) in self.addrs.iter() {
            if p == peer_id {
                list.push(a.clone());
            }
        }
        list
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        endpoint: &ConnectedPoint,
        failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        self.inner
            .inject_connection_established(peer_id, conn, endpoint, failed_addresses, other_established)
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        endpoint: &ConnectedPoint,
        handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
        self.inner
            .inject_connection_closed(peer_id, conn, endpoint, handler, remaining_established)
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
        self.inner.inject_event(peer_id, connection, event)
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        handler: Self::ConnectionHandler,
        error: &DialError,
    ) {
        self.inner.inject_dial_failure(peer_id, handler, error)
    }

    fn inject_new_listener(&mut self, id: ListenerId) {
        self.inner.inject_new_listener(id)
    }

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        self.inner.inject_new_listen_addr(id, addr)
    }

    fn inject_expired_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        self.inner.inject_expired_listen_addr(id, addr)
    }

    fn inject_listener_error(&mut self, id: ListenerId, err: &(dyn error::Error + 'static)) {
        self.inner.inject_listener_error(id, err);
    }

    fn inject_listener_closed(&mut self, id: ListenerId, reason: Result<(), &io::Error>) {
        self.inner.inject_listener_closed(id, reason);
    }

    fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
        self.inner.inject_new_external_addr(addr)
    }

    fn inject_expired_external_addr(&mut self, addr: &Multiaddr) {
        self.inner.inject_expired_external_addr(addr)
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        self.inner.poll(cx, params)
    }
}

pub fn build_node(
    keypair: Keypair,
    self_addr: Multiaddr,
    peers_addrs: Vec<(PeerId, Multiaddr)>,
    local_status: NodeStatus,
) -> (
    Swarm<CustomProtoWithAddr>,
    ProtocolHandler<SyncBehaviour, NetworkMailbox>,
) {
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .unwrap();

    let transport = MemoryTransport::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(yamux::YamuxConfig::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    let peer_conn_handler_conf = PeerConnHandlerConf {
        async_msg_buffer_size: 10,
        sync_msg_buffer_size: 40,
        open_timeout: Duration::from_secs(60),
        initial_keep_alive: Duration::from_secs(60),
    };
    let peer_index_conf = PeerIndexConfig {
        max_incoming: 25,
        max_outgoing: 50,
    };
    let peer_manager_conf = PeerManagerConfig {
        min_reputation: Reputation::from(10),
        conn_reset_outbound_backoff: Duration::from_secs(120),
        periodic_conn_interval: Duration::from_secs(30),
        protocols_allocation: Vec::new(),
    };
    let peer_state = PeersStateDef::new(peer_index_conf);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let sync_conf = ProtocolConfig {
        supported_versions: vec![(
            SyncSpec::v1(),
            ProtocolSpec {
                max_message_size: 100,
                handshake_required: true,
            },
        )],
    };
    let sync_behaviour = SyncBehaviour::new(local_status);
    let (requests_snd, requests_recv) = mpsc::unbounded::<NetworkControllerIn>();
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };
    let (sync_handler, sync_mailbox) = ProtocolHandler::new(sync_behaviour, network_api);
    let nc = NetworkController::new(
        peer_conn_handler_conf,
        HashMap::from([(SYNC_PROTOCOL_ID, (sync_conf, sync_mailbox))]),
        peers,
        peer_manager,
        requests_recv,
    );
    let behaviour = CustomProtoWithAddr {
        inner: nc,
        addrs: peers_addrs,
    };

    let mut swarm = Swarm::new(transport, behaviour, keypair.public().to_peer_id());
    swarm.listen_on(self_addr).unwrap();

    (swarm, sync_handler)
}

/// Builds two nodes that have each other as bootstrap nodes.
/// This is to be used only for testing, and a panic will happen if something goes wrong.
pub fn build_nodes(
    n: usize,
) -> Vec<(
    Swarm<CustomProtoWithAddr>,
    ProtocolHandler<SyncBehaviour, NetworkMailbox>,
)> {
    let mut out = Vec::with_capacity(n);

    let keypairs: Vec<_> = (0..n).map(|_| identity::Keypair::generate_ed25519()).collect();
    let addrs: Vec<Multiaddr> = (0..n)
        .map(|_| format!("/memory/{}", rand::random::<u64>()).parse().unwrap())
        .collect();

    for index in 0..n {
        let keypair = keypairs[index].clone();
        let addr = addrs[index].clone();
        let peers = addrs
            .iter()
            .enumerate()
            .filter_map(|(n, a)| {
                if n != index {
                    Some((keypairs[n].public().to_peer_id(), a.clone()))
                } else {
                    None
                }
            })
            .collect();

        let status = NodeStatus {
            supported_protocols: Vec::from([SYNC_PROTOCOL_ID]),
            height: 0,
        };
        out.push(build_node(keypair, addr, peers, status));
    }

    out
}
