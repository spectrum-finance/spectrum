use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::ops::Add;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::channel::oneshot::{Receiver, Sender};
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt, Stream};
use libp2p::swarm::ConnectionId;
use libp2p::PeerId;
use log::{error, info, trace};
use wasm_timer::Delay;

use crate::peer_conn_handler::ConnHandlerError;
use crate::peer_manager::data::{
    ConnectionLossReason, ConnectionState, PeerDestination, PeerInfo, ProtocolAllocationPolicy,
    ReputationChange,
};
use crate::peer_manager::peers_state::{NetworkingState, PeerInState, PeerStateFilter, PeersState};
use crate::types::{ProtocolId, Reputation};

pub mod data;
pub mod peer_index;
pub mod peers_state;

/// Peer Manager output commands.
#[derive(Debug, PartialEq, Eq)]
pub enum PeerManagerOut {
    /// Request to open a connection to the given peer.
    Connect(PeerDestination),
    /// Drop the connection to the given peer, or cancel the connection attempt after a `Connect`.
    Drop(PeerId),
    /// Approves an incoming connection.
    AcceptIncomingConnection(PeerId, ConnectionId),
    /// Rejects an incoming connection.
    Reject(PeerId, ConnectionId),
    /// An instruction to start the specified protocol with the specified peer.
    StartProtocol(ProtocolId, PeerId),
    /// Notify that a peer was punished.
    NotifyPeerPunished {
        peer_id: PeerId,
        reason: ReputationChange,
    },
}

/// Peer Manager inputs.
#[derive(Debug)]
pub enum PeerManagerRequest {
    AddPeers(Vec<PeerDestination>),
    AddReservedPeer(PeerDestination),
    SetReservedPeers(HashSet<PeerId>),
    ReportPeer(PeerId, ReputationChange),
    GetPeerReputation(PeerId, Sender<Reputation>),
    GetPeers {
        limit: usize,
        snd: Sender<Vec<PeerDestination>>,
    },
    /// Update set of protocols that the given peer supports.
    SetProtocols(PeerId, Vec<ProtocolId>),
}

/// Events Peer Manager reacts to.
#[derive(Debug)]
pub enum PeerEvent {
    IncomingConnection(PeerId, ConnectionId),
    ConnectionEstablished(PeerId, ConnectionId),
    ConnectionLost(PeerId, ConnectionLossReason),
    DialFailure(PeerId),
    /// Specified protocol is enabled with the specified peer by the ProtocolHandler.
    ForceEnabled(PeerId, ProtocolId),
}

pub enum PeerManagerIn {
    Notification(PeerEvent),
    Request(PeerManagerRequest),
}

/// Async API to PeerManager.
pub trait Peers {
    /// Add given peers to PM.
    fn add_peers(&mut self, peers: Vec<PeerDestination>);
    /// Get peers known to PM.
    fn get_peers(&mut self, limit: usize) -> Receiver<Vec<PeerDestination>>;
    /// Add reserved peer.
    fn add_reserved_peer(&mut self, peer_id: PeerDestination);
    /// Update set of reserved peers.
    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    /// Report peer behaviour.
    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    /// Get reputation of the given peer.
    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation>;
    /// Update the set of peer protocols.
    fn set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>);
}

/// Async API to PeerManager notifications.
pub trait PeerEvents {
    fn incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
    fn dial_failure(&mut self, peer_id: PeerId);
    fn force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId);
}

pub trait PeerManagerRequestsBehavior {
    fn on_add_peers(&mut self, peers: Vec<PeerDestination>);
    fn on_get_peers(&mut self, limit: usize, response: Sender<Vec<PeerDestination>>);
    fn on_add_reserved_peer(&mut self, peer_id: PeerDestination);
    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    fn on_report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: Sender<Reputation>);
    fn on_set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>);
}

pub trait PeerManagerNotificationsBehavior {
    fn on_incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn on_connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
    fn on_dial_failure(&mut self, peer_id: PeerId);
    fn on_force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId);
}

#[derive(Clone)]
pub struct PeersMailbox {
    mailbox_snd: mpsc::Sender<PeerManagerIn>,
}

impl Peers for PeersMailbox {
    fn add_peers(&mut self, peers: Vec<PeerDestination>) {
        let _ = futures::executor::block_on(
            self.mailbox_snd
                .clone()
                .send(PeerManagerIn::Request(PeerManagerRequest::AddPeers(peers))),
        );
    }

    fn get_peers(&mut self, limit: usize) -> Receiver<Vec<PeerDestination>> {
        let (sender, receiver) = oneshot::channel::<Vec<PeerDestination>>();
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::GetPeers { limit, snd: sender },
        )));
        receiver
    }

    fn add_reserved_peer(&mut self, peer_id: PeerDestination) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::AddReservedPeer(peer_id),
        )));
    }

    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::SetReservedPeers(peers),
        )));
    }

    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::ReportPeer(peer_id, change),
        )));
    }

    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation> {
        let (sender, receiver) = oneshot::channel::<Reputation>();
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::GetPeerReputation(peer_id, sender),
        )));
        receiver
    }

    fn set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Request(
            PeerManagerRequest::SetProtocols(peer_id, protocols),
        )));
    }
}

impl PeerEvents for PeersMailbox {
    fn incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Notification(
            PeerEvent::IncomingConnection(peer_id, conn_id),
        )));
    }

    fn connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Notification(
            PeerEvent::ConnectionEstablished(peer_id, conn_id),
        )));
    }

    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Notification(
            PeerEvent::ConnectionLost(peer_id, reason),
        )));
    }

    fn dial_failure(&mut self, peer_id: PeerId) {
        let _ = futures::executor::block_on(
            self.mailbox_snd
                .clone()
                .send(PeerManagerIn::Notification(PeerEvent::DialFailure(peer_id))),
        );
    }

    fn force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId) {
        let _ = futures::executor::block_on(self.mailbox_snd.clone().send(PeerManagerIn::Notification(
            PeerEvent::ForceEnabled(peer_id, protocol_id),
        )));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct NetworkingConfig {
    /// Minimal number of known peers.
    /// If not satisfied, node will have to use bootstrapping peers.
    pub min_known_peers: usize,
    /// Minimal number of outbound connections for the node to be deemed as bootstrapped.
    pub min_outbound: usize,
    /// Maximal number of inbound connections the node can accept.
    pub max_inbound: usize,
    /// Maximal number of outbound connections the node can establish.
    pub max_outbound: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerManagerConfig {
    /// The minimum allowable reputation for a connected peer. A peer with reputation below this
    /// value is classed as unacceptable, and its connection should be dropped.
    pub min_acceptable_reputation: Reputation,
    /// Represents the minimum reputation a peer must have to accept its incoming connection.
    pub min_reputation: Reputation,
    pub conn_reset_outbound_backoff: Duration,
    pub conn_alloc_interval: Duration,
    pub prot_alloc_interval: Duration,
    pub protocols_allocation: Vec<(ProtocolId, ProtocolAllocationPolicy)>,
    pub peer_manager_msg_buffer_size: usize,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConnAllocationMode {
    Active,
    Passive,
    Idle,
}

const ACTIVE_CONN_ALLOC_INTERVAL: Duration = Duration::from_secs(1);

pub struct PeerManager<TState> {
    state: TState,
    conf: PeerManagerConfig,
    mailbox: mpsc::Receiver<PeerManagerIn>,
    out_queue: VecDeque<PeerManagerOut>,
    next_conn_alloc: Delay,
    next_prot_alloc: Delay,
    boot_in_progress: bool,
}

impl<S: PeersState> PeerManager<S> {
    pub fn new(state: S, conf: PeerManagerConfig) -> (Self, PeersMailbox) {
        let (snd, recv) = mpsc::channel::<PeerManagerIn>(conf.peer_manager_msg_buffer_size);
        let pm = Self {
            state,
            conf,
            mailbox: recv,
            out_queue: VecDeque::new(),
            next_conn_alloc: Delay::new(Duration::new(0, 0)),
            next_prot_alloc: Delay::new(Duration::new(0, 0)),
            boot_in_progress: false,
        };
        let peers = PeersMailbox { mailbox_snd: snd };
        (pm, peers)
    }

    /// Connect to reserved peers we are not connected yet.
    pub fn connect_reserved(&mut self) {
        let peers = self.state.get_reserved_peers(Some(PeerStateFilter::NotConnected));
        for pid in peers.iter() {
            self.connect(pid)
        }
    }

    /// Connect to the best peer we are not connected yet.
    pub fn connect_best(&mut self) {
        trace!("Going to connect best known peer");
        if let Some(pid) = self.state.pick_best(Some(|_: &PeerId, pi: &PeerInfo| {
            matches!(pi.state, ConnectionState::NotConnected)
        })) {
            trace!("Going to connect peer {}", pid);
            self.connect(&pid)
        }
    }

    /// Connect to a known peer.
    fn connect(&mut self, peer_id: &PeerId) {
        trace!("Connect(peer_id={})", peer_id);
        if let Some(PeerInState::NotConnected(ncp)) = self.state.peer(peer_id) {
            if ncp
                .backoff_until()
                .map(|backoff_until| backoff_until <= Instant::now())
                .unwrap_or(true)
            {
                let cp = ncp.connect();
                self.out_queue
                    .push_back(PeerManagerOut::Connect(cp.destination()))
            }
        }
    }

    /// Disconnect a known peer.
    fn disconnect(&mut self, peer_id: PeerId, forget: bool) {
        if let Some(PeerInState::Connected(cp)) = self.state.peer(&peer_id) {
            let ncp = cp.disconnect();
            trace!("Peer {} disconnected", peer_id);
            if forget {
                ncp.forget();
                trace!("Peer {} forgotten", peer_id);
            }
            self.out_queue.push_back(PeerManagerOut::Drop(peer_id));
        } else {
            error!("Cannot disconnect peer {}", peer_id);
        }
    }

    /// Prepare for new conn allocation cycle.
    fn prepare_allocate_connections(&mut self) -> ConnAllocationMode {
        match self.state.networking_state() {
            NetworkingState::NotBootstrapped(boot_peers) => {
                let mut added = 0;
                for p in boot_peers.into_iter() {
                    if self.state.try_add_peer(p, false, true).is_some() {
                        added += 1;
                    }
                }
                trace!("Node not bootstrapped. {} peers added.", added);
                ConnAllocationMode::Active
            }
            NetworkingState::BootInProgress => {
                self.boot_in_progress = true;
                ConnAllocationMode::Active
            }
            NetworkingState::Bootstrapped => {
                if self.boot_in_progress {
                    for pid in self
                        .state
                        .filter_peers(|_: &PeerId, pif: &PeerInfo| pif.is_boot && pif.state.is_connected())
                        .into_iter()
                    {
                        self.disconnect(pid, true);
                    }
                    self.boot_in_progress = false;
                }
                ConnAllocationMode::Passive
            }
            NetworkingState::Saturated => ConnAllocationMode::Idle,
        }
    }

    /// Allocate protocol substreams according to configured policies.
    fn allocate_protocols(&mut self) {
        for (prot, policy) in self.conf.protocols_allocation.clone().iter() {
            if let Some(enabled_peers) = self.state.get_enabled_peers(prot) {
                let cond = match policy {
                    ProtocolAllocationPolicy::Bounded(max_conn_percent) => {
                        enabled_peers.len() / self.state.num_connected_peers() < *max_conn_percent / 100
                    }
                    ProtocolAllocationPolicy::Max => enabled_peers.len() < self.state.num_connected_peers(),
                    ProtocolAllocationPolicy::Zero => false,
                };
                if cond {
                    if let Some(candidate) = self.state.pick_best(Some(|pid: &PeerId, pi: &PeerInfo| {
                        !enabled_peers.contains(pid) && pi.supports(prot).unwrap_or(false)
                    })) {
                        if let Some(PeerInState::Connected(mut cp)) = self.state.peer(&candidate) {
                            cp.enable_protocol(*prot);
                            self.out_queue
                                .push_back(PeerManagerOut::StartProtocol(*prot, candidate));
                        }
                    }
                }
            }
        }
    }
}

impl<S: PeersState> PeerManagerRequestsBehavior for PeerManager<S> {
    fn on_add_peers(&mut self, peers: Vec<PeerDestination>) {
        for p in peers {
            let pid = p.peer_id();
            if self.state.try_add_peer(p, false, false).is_some() {
                info!("New peer {:?} added", pid);
            }
        }
    }

    fn on_get_peers(&mut self, limit: usize, response: Sender<Vec<PeerDestination>>) {
        trace!("on_get_peers()");
        let peers = self.state.get_peers(limit);
        let _ = response.send(peers);
        trace!("on_get_peers() -> ()");
    }

    fn on_add_reserved_peer(&mut self, peer_id: PeerDestination) {
        self.state.try_add_peer(peer_id, true, false);
    }

    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let unkown_peers = self.state.set_reserved_peers(peers);
        for pid in unkown_peers {
            self.state.try_add_peer(PeerDestination::PeerId(pid), true, false);
        }
    }

    fn on_report_peer(&mut self, peer_id: PeerId, adjustment: ReputationChange) {
        if let Some(peer) = self.state.peer(&peer_id) {
            if adjustment.is_downgrade() {
                self.out_queue.push_back(PeerManagerOut::NotifyPeerPunished {
                    peer_id,
                    reason: adjustment,
                });
            }

            // A peer with reputation below self.conf.min_acceptable_reputation is classed as
            // unacceptable, and its connection will be dropped.
            let is_acceptable = peer
                .adjust_reputation(adjustment)
                .is_reputation_acceptable(self.conf.min_acceptable_reputation);

            if !is_acceptable {
                self.disconnect(peer_id, true);
            }
        }
    }

    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: Sender<Reputation>) {
        if let Some(peer) = self.state.peer(&peer_id) {
            let reputation = peer.get_reputation();
            let _ = response.send(reputation);
        }
    }

    fn on_set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>) {
        if let Some(mut peer) = self.state.peer(&peer_id) {
            peer.set_protocols(protocols);
        }
    }
}

impl<S: PeersState> PeerManagerNotificationsBehavior for PeerManager<S> {
    fn on_incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        trace!("on_incoming_connection(peer_id={})", peer_id);
        match self.state.peer(&peer_id) {
            Some(PeerInState::NotConnected(ncp)) => {
                if ncp.get_reputation() >= self.conf.min_reputation && ncp.try_accept_connection().is_ok() {
                    trace!("Accepting connection from {}", peer_id);
                    self.out_queue
                        .push_back(PeerManagerOut::AcceptIncomingConnection(peer_id, conn_id));
                } else {
                    trace!("Rejecting connection from {}", peer_id);
                    self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                }
            }
            Some(PeerInState::Connected(_)) => {
                trace!("Already connected. Rejecting connection from {}", peer_id);
                self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
            }
            None => {
                if let Some(ncp) = self
                    .state
                    .try_add_peer(PeerDestination::PeerId(peer_id), false, false)
                {
                    if ncp.try_accept_connection().is_ok() {
                        trace!("Peer is unknown. Accepting connection from {}", peer_id);
                        self.out_queue
                            .push_back(PeerManagerOut::AcceptIncomingConnection(peer_id, conn_id));
                    } else {
                        trace!("Peer is unknown. Rejecting connection from {}", peer_id);
                        self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                    }
                } else {
                    trace!("Peer is unknown. Rejecting connection from {}", peer_id);
                    self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                }
            }
        }
    }

    fn on_connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        if let Some(PeerInState::Connected(mut cp)) = self.state.peer(&peer_id) {
            trace!("Peer {} has been acknowledged as connected", peer_id);
            cp.confirm_connection();
        } else {
            error!("Peer {} hasn't been acknowledged as connected", peer_id)
        }
    }

    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        match self.state.peer(&peer_id) {
            Some(PeerInState::Connected(cp)) => {
                let mut ncp = cp.disconnect();
                match reason {
                    ConnectionLossReason::ResetByPeer => {
                        if !ncp.is_reserved() {
                            let backoff_until = Instant::now().add(self.conf.conn_reset_outbound_backoff);
                            ncp.set_backoff_until(backoff_until);
                        }
                    }
                    ConnectionLossReason::Reset(err) => match err {
                        ConnHandlerError::SyncChannelExhausted => {
                            self.on_report_peer(peer_id, ReputationChange::TooSlow);
                        }
                        ConnHandlerError::UnacceptablePeer => (),
                    },
                    ConnectionLossReason::Unknown => {}
                }
            }
            Some(PeerInState::NotConnected(_)) => {} // warn
            None => {}                               // warn
        }
    }

    fn on_dial_failure(&mut self, peer_id: PeerId) {
        match self.state.peer(&peer_id) {
            Some(PeerInState::Connected(_)) => {
                trace!("ON DIAL FAILURE: {:?} already connected", peer_id);
                self.on_report_peer(peer_id, ReputationChange::NoResponse);
            }
            Some(PeerInState::NotConnected(_)) => {
                trace!("ON DIAL FAILURE: {:?} NOT connected", peer_id);
            } // warn
            None => {
                trace!("ON DIAL FAILURE: {:?} unknown peer", peer_id);
            } // warn
        }
    }

    fn on_force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId) {
        if let Some(PeerInState::Connected(mut cp)) = self.state.peer(&peer_id) {
            cp.enable_protocol(protocol_id);
        }
    }
}

impl<S: Unpin + PeersState> Stream for PeerManager<S> {
    type Item = PeerManagerOut;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(out) = self.out_queue.pop_front() {
                return Poll::Ready(Some(out));
            }

            if let Poll::Ready(Some(notif)) = Stream::poll_next(Pin::new(&mut self.mailbox), cx) {
                match notif {
                    PeerManagerIn::Notification(notification) => match notification {
                        PeerEvent::IncomingConnection(pid, conn_id) => {
                            self.on_incoming_connection(pid, conn_id)
                        }
                        PeerEvent::ConnectionEstablished(pid, conn_id) => {
                            self.on_connection_established(pid, conn_id)
                        }
                        PeerEvent::ConnectionLost(pid, reason) => self.on_connection_lost(pid, reason),
                        PeerEvent::DialFailure(pid) => self.on_dial_failure(pid),
                        PeerEvent::ForceEnabled(pid, protocol_id) => {
                            self.on_force_enabled(pid, protocol_id);
                        }
                    },
                    PeerManagerIn::Request(req) => match req {
                        PeerManagerRequest::AddPeers(peers) => self.on_add_peers(peers),
                        PeerManagerRequest::GetPeers { limit, snd } => self.on_get_peers(limit, snd),
                        PeerManagerRequest::ReportPeer(pid, adjustment) => {
                            self.on_report_peer(pid, adjustment);
                        }
                        PeerManagerRequest::AddReservedPeer(pid) => self.on_add_reserved_peer(pid),
                        PeerManagerRequest::GetPeerReputation(pid, resp) => {
                            self.on_get_peer_reputation(pid, resp)
                        }
                        PeerManagerRequest::SetReservedPeers(peers) => self.on_set_reserved_peers(peers),
                        PeerManagerRequest::SetProtocols(pid, protocols) => {
                            self.on_set_peer_protocols(pid, protocols)
                        }
                    },
                }
                continue;
            }

            if Future::poll(Pin::new(&mut self.next_conn_alloc), cx).is_ready() {
                trace!("Going to allocate more connections");
                self.connect_reserved(); // always try to allocate connections to reserved peers.
                match self.prepare_allocate_connections() {
                    ConnAllocationMode::Active => {
                        self.connect_best();
                        self.next_conn_alloc = Delay::new(ACTIVE_CONN_ALLOC_INTERVAL)
                    }
                    ConnAllocationMode::Passive => {
                        self.connect_best();
                        self.next_conn_alloc = Delay::new(self.conf.conn_alloc_interval)
                    }
                    ConnAllocationMode::Idle => {
                        self.next_conn_alloc = Delay::new(self.conf.conn_alloc_interval)
                    }
                }
            }

            if Future::poll(Pin::new(&mut self.next_prot_alloc), cx).is_ready() {
                self.allocate_protocols();
                self.next_prot_alloc = Delay::new(self.conf.prot_alloc_interval);
            }

            return Poll::Pending;
        }
    }
}
