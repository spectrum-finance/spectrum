use std::{collections::HashMap, time::Duration};

use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use libp2p::{identity, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};
use spectrum_network::{
    network_controller::{NetworkController, NetworkControllerIn, NetworkControllerOut, NetworkMailbox},
    peer_conn_handler::PeerConnHandlerConf,
    peer_manager::{
        data::PeerDestination, peers_state::PeerRepo, NetworkingConfig, PeerManager, PeerManagerConfig,
        PeersMailbox,
    },
    protocol::{ProtocolConfig, ProtocolSpec, SYNC_PROTOCOL_ID},
    protocol_api::ProtocolMailbox,
    protocol_handler::{
        sync::{message::SyncSpec, NodeStatus, SyncBehaviour},
        ProtocolHandler,
    },
    types::Reputation,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Peer {
    First,
    Second,
}

#[async_std::test]
async fn integration_test() {
    // In this test we have 2 peers `peer_0` and `peer_1`. `peer_0` is initialised without any
    // bootstrap peers but `peer_1` has `peer_0` as a bootstrap peer. This ensures that `peer_1`
    // will initiate a connection with `peer_0`.

    let local_key_0 = identity::Keypair::generate_ed25519();
    let local_peer_id_0 = PeerId::from(local_key_0.public());
    let local_key_1 = identity::Keypair::generate_ed25519();
    let local_peer_id_1 = PeerId::from(local_key_1.public());

    let addr_0: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
    let addr_1: Multiaddr = "/ip4/127.0.0.1/tcp/1235".parse().unwrap();
    let peers_0 = vec![PeerDestination::PeerIdWithAddr(local_peer_id_1, addr_1.clone())];
    let peers_1 = vec![PeerDestination::PeerIdWithAddr(local_peer_id_0, addr_0.clone())];

    let (nc_out_tx, mut nc_out_rx) = mpsc::channel(10);
    let peer_0 = make_swarm_fut(vec![], local_key_0, addr_0, Peer::First, nc_out_tx.clone());
    let peer_1 = make_swarm_fut(peers_1, local_key_1, addr_1, Peer::Second, nc_out_tx);
    let (abortable_peer_0, handle_0) = futures::future::abortable(peer_0);
    let (abortable_peer_1, handle_1) = futures::future::abortable(peer_1);
    let (cancel_tx_0, cancel_rx_0) = oneshot::channel::<()>();
    let (cancel_tx_1, cancel_rx_1) = oneshot::channel::<()>();

    // Spawn tasks for peer_0
    async_std::task::spawn(async move {
        let _ = cancel_rx_0.await;
        handle_0.abort();
    });
    async_std::task::spawn(async move {
        wasm_timer::Delay::new(Duration::from_secs(3)).await.unwrap();
        cancel_tx_0.send(()).unwrap();
    });
    async_std::task::spawn(abortable_peer_0);

    // Spawn tasks for peer_1
    async_std::task::spawn(async move {
        let _ = cancel_rx_1.await;
        handle_1.abort();
    });
    async_std::task::spawn(async move {
        wasm_timer::Delay::new(Duration::from_secs(3)).await.unwrap();
        cancel_tx_1.send(()).unwrap();
    });
    async_std::task::spawn(abortable_peer_1);

    let mut res_peer_0 = vec![];
    while let Some((peer, nc_msg)) = nc_out_rx.next().await {
        match peer {
            Peer::First => res_peer_0.push(nc_msg),
            Peer::Second => (),
        }
    }
    dbg!(&res_peer_0);
    assert!(
        if let Some(NetworkControllerOut::ConnectedWithInboundPeer(pid)) = res_peer_0.first() {
            *pid == local_peer_id_1
        } else {
            false
        }
    );
}

async fn make_swarm_fut(
    peers: Vec<PeerDestination>,
    local_key: identity::Keypair,
    addr: Multiaddr,
    peer: Peer,
    mut tx: mpsc::Sender<(Peer, NetworkControllerOut)>,
) {
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
    let local_peer_id = PeerId::from(local_key.public());
    let transport = libp2p::development_transport(local_key).await.unwrap();
    let peer_state = PeerRepo::new(netw_config, peers.clone());
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

    let mut swarm = Swarm::new(transport, nc, local_peer_id);
    async_std::task::spawn(async move {
        loop {
            let _ = sync_handler.select_next_some().await;
        }
    });

    swarm.listen_on(addr).unwrap();

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
            SwarmEvent::Behaviour(event) => {
                if let NetworkControllerOut::ConnectedWithInboundPeer(_) = event {
                    tx.try_send((peer, event)).unwrap();
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => println!("New conn {:?}", peer_id),
            _ => {}
        }
    }
}
