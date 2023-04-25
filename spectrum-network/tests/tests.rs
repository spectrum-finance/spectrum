use std::collections::HashMap;
use std::{
    error, io,
    task::{Context, Poll},
    time::Duration,
};

use futures::channel::mpsc;
use libp2p::core::Endpoint;
use libp2p::identity::Keypair;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, SwarmBuilder, THandler, THandlerInEvent, THandlerOutEvent,
    ToSwarm,
};
use libp2p::{
    core::{
        transport::{ListenerId, MemoryTransport},
        upgrade, ConnectedPoint,
    },
    identity, noise,
    swarm::{ConnectionHandler, DialError, NetworkBehaviour, PollParameters, Swarm},
    yamux, Multiaddr, PeerId, Transport,
};

use spectrum_network::network_controller::{NetworkController, NetworkControllerIn, NetworkMailbox};
use spectrum_network::peer_conn_handler::{ConnHandlerIn, PeerConnHandlerConf};
use spectrum_network::peer_manager::data::PeerDestination;
use spectrum_network::peer_manager::peers_state::PeerRepo;
use spectrum_network::peer_manager::{NetworkingConfig, PeerManager, PeerManagerConfig, PeersMailbox};
use spectrum_network::protocol::{StatefulProtocolConfig, StatefulProtocolSpec, SYNC_PROTOCOL_ID};
use spectrum_network::protocol_api::ProtocolMailbox;
use spectrum_network::protocol_handler::sync::message::SyncSpec;
use spectrum_network::protocol_handler::sync::{NodeStatus, SyncBehaviour};
use spectrum_network::protocol_handler::ProtocolHandler;
use spectrum_network::types::Reputation;

#[cfg(feature = "integration_tests")]
mod integration_tests;
mod peer_manager;

/// Wraps around the `CustomBehaviour` network behaviour, and adds hardcoded node addresses to it.
pub struct CustomProtoWithAddr {
    inner: NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>,
    addrs: Vec<(PeerId, Multiaddr)>,
}

impl std::ops::Deref for CustomProtoWithAddr {
    type Target = NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox>;

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
    type ConnectionHandler = <NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox> as NetworkBehaviour>::ConnectionHandler;
    type OutEvent = <NetworkController<PeersMailbox, PeerManager<PeerRepo>, ProtocolMailbox> as NetworkBehaviour>::OutEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(_connection_id, peer, local_addr, remote_addr)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_outbound_connection(_connection_id, peer, addr, role_override)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(_peer_id, _connection_id, _event)
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::OutEvent, THandlerInEvent<Self>>> {
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
    ProtocolHandler<SyncBehaviour<PeersMailbox>, NetworkMailbox>,
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
    let peer_manager_conf = PeerManagerConfig {
        min_acceptable_reputation: Reputation::from(0),
        min_reputation: Reputation::from(10),
        conn_reset_outbound_backoff: Duration::from_secs(120),
        conn_alloc_interval: Duration::from_secs(30),
        protocols_allocation: Vec::new(),
        prot_alloc_interval: Duration::from_secs(30),
    };
    let netw_conf = NetworkingConfig {
        min_known_peers: 2,
        min_outbound: 1,
        max_inbound: 25,
        max_outbound: 50,
    };
    let boot_peers = vec![
        PeerDestination::PeerId(PeerId::random()),
        PeerDestination::PeerId(PeerId::random()),
        PeerDestination::PeerId(PeerId::random()),
    ];
    let peer_state = PeerRepo::new(netw_conf, boot_peers);
    let (peer_manager, peers) = PeerManager::new(peer_state, peer_manager_conf);
    let sync_conf = StatefulProtocolConfig {
        supported_versions: vec![(
            SyncSpec::v1(),
            StatefulProtocolSpec {
                max_message_size: 100,
                approve_required: true,
            },
        )],
    };
    let sync_behaviour = SyncBehaviour::new(peers.clone(), local_status);
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

    let mut swarm =
        SwarmBuilder::with_async_std_executor(transport, behaviour, keypair.public().to_peer_id()).build();
    swarm.listen_on(self_addr).unwrap();

    (swarm, sync_handler)
}

/// Builds two nodes that have each other as bootstrap nodes.
/// This is to be used only for testing, and a panic will happen if something goes wrong.
#[allow(clippy::type_complexity)]
pub fn build_nodes(
    n: usize,
) -> Vec<(
    Swarm<CustomProtoWithAddr>,
    ProtocolHandler<SyncBehaviour<PeersMailbox>, NetworkMailbox>,
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
