pub mod data;
pub mod peer_index;
pub mod peers_state;

use crate::peer_conn_handler::ConnHandlerError;
use crate::peer_manager::data::{
    ConnectionLossReason, ConnectionState, PeerIdentity, PeerInfo, ProtocolAllocationPolicy, ReputationChange,
};
use crate::peer_manager::peers_state::{PeerInState, PeerStateFilter, PeersState};
use crate::types::{ProtocolId, Reputation};
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot::Receiver;
use futures::channel::{mpsc, oneshot};
use futures::Stream;
use libp2p::core::connection::ConnectionId;
use libp2p::PeerId;
use log::{error, warn};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::ops::Add;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use wasm_timer::Delay;

/// Peer Manager output commands.
#[derive(Debug, PartialEq)]
pub enum PeerManagerOut {
    /// Request to open a connection to the given peer.
    Connect(PeerIdentity),
    /// Drop the connection to the given peer, or cancel the connection attempt after a `Connect`.
    Drop(PeerId),
    /// Approves an incoming connection.
    Accept(PeerId, ConnectionId),
    /// Rejects an incoming connection.
    Reject(PeerId, ConnectionId),
    /// An instruction to start the specified protocol with the specified peer.
    StartProtocol(ProtocolId, PeerId),
}

/// Peer Manager inputs.
#[derive(Debug)]
pub enum PeerManagerRequest {
    AddPeer(PeerIdentity),
    AddReservedPeer(PeerIdentity),
    SetReservedPeers(HashSet<PeerId>),
    ReportPeer(PeerId, ReputationChange),
    GetPeerReputation(PeerId, oneshot::Sender<Reputation>),
    /// Update set of protocols that the given peer supports.
    SetProtocols(PeerId, Vec<ProtocolId>),
}

/// Events Peer Manager reacts to.
#[derive(Debug)]
pub enum PeerEvent {
    IncomingConnection(PeerId, ConnectionId),
    ConnectionEstablished(PeerId, ConnectionId),
    ConnectionLost(PeerId, ConnectionLossReason),
    /// Specified protocol is enabled with the specified peer by the ProtocolHandler.
    ForceEnabled(PeerId, ProtocolId),
}

pub enum PeerManagerIn {
    Notification(PeerEvent),
    Request(PeerManagerRequest),
}

/// Async API to PeerManager.
pub trait PeerActions {
    fn add_peer(&mut self, peer_id: PeerIdentity);
    fn add_reserved_peer(&mut self, peer_id: PeerIdentity);
    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation>;
    fn set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>);
}

/// Async API to PeerManager notifications.
pub trait PeerEvents {
    fn incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
    fn force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId);
}

pub trait PeerManagerRequestsBehavior {
    fn on_add_peer(&mut self, peer_id: PeerIdentity);
    fn on_add_reserved_peer(&mut self, peer_id: PeerIdentity);
    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    fn on_report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: oneshot::Sender<Reputation>);
    fn on_set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>);
}

pub trait PeerManagerNotificationsBehavior {
    fn on_incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn on_connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId);
    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
    fn on_force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId);
}

pub struct PeersMailbox {
    mailbox_snd: UnboundedSender<PeerManagerIn>,
}

impl PeerActions for PeersMailbox {
    fn add_peer(&mut self, peer_id: PeerIdentity) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::AddPeer(peer_id)));
    }

    fn add_reserved_peer(&mut self, peer_id: PeerIdentity) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::AddReservedPeer(
                peer_id,
            )));
    }

    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let _ =
            self.mailbox_snd
                .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::SetReservedPeers(
                    peers,
                )));
    }

    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::ReportPeer(
                peer_id, change,
            )));
    }

    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation> {
        let (sender, receiver) = oneshot::channel::<Reputation>();
        let _ =
            self.mailbox_snd
                .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::GetPeerReputation(
                    peer_id, sender,
                )));
        receiver
    }

    fn set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Request(PeerManagerRequest::SetProtocols(
                peer_id, protocols,
            )));
    }
}

impl PeerEvents for PeersMailbox {
    fn incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Notification(PeerEvent::IncomingConnection(
                peer_id, conn_id,
            )));
    }

    fn connection_established(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        let _ =
            self.mailbox_snd
                .unbounded_send(PeerManagerIn::Notification(PeerEvent::ConnectionEstablished(
                    peer_id, conn_id,
                )));
    }

    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Notification(PeerEvent::ConnectionLost(
                peer_id, reason,
            )));
    }

    fn force_enabled(&mut self, peer_id: PeerId, protocol_id: ProtocolId) {
        let _ = self
            .mailbox_snd
            .unbounded_send(PeerManagerIn::Notification(PeerEvent::ForceEnabled(
                peer_id,
                protocol_id,
            )));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerManagerConfig {
    pub min_reputation: Reputation,
    pub conn_reset_outbound_backoff: Duration,
    pub periodic_conn_interval: Duration,
    pub protocols_allocation: Vec<(ProtocolId, ProtocolAllocationPolicy)>,
}

pub struct PeerManager<TState> {
    state: TState,
    conf: PeerManagerConfig,
    mailbox: UnboundedReceiver<PeerManagerIn>,
    out_queue: VecDeque<PeerManagerOut>,
    next_conn_alloc: Delay,
}

impl<S: PeersState> PeerManager<S> {
    pub fn new(state: S, conf: PeerManagerConfig) -> (Self, PeersMailbox) {
        let (snd, recv) = mpsc::unbounded::<PeerManagerIn>();
        let pm = Self {
            state,
            conf,
            mailbox: recv,
            out_queue: VecDeque::new(),
            next_conn_alloc: Delay::new(Duration::new(0, 0)),
        };
        let peers = PeersMailbox { mailbox_snd: snd };
        (pm, peers)
    }

    pub fn alloc_conns(&self) {

    }

    /// Connect to reserved peers we are not connected yet.
    pub fn connect_reserved(&mut self) {
        let peers = self.state.get_reserved_peers(Some(PeerStateFilter::NotConnected));
        for pid in peers {
            self.connect(pid)
        }
    }

    /// Connect to the best peer we are not connected yet.
    pub fn connect_best(&mut self) {
        if let Some(pid) = self.state.peek_best(Some(|_: &PeerId, pi: &PeerInfo| {
            matches!(pi.state, ConnectionState::NotConnected)
        })) {
            self.connect(pid)
        }
    }

    /// Connect to a known peer.
    fn connect(&mut self, peer_id: PeerId) {
        if let Some(PeerInState::NotConnected(ncp)) = self.state.peer(&peer_id) {
            let should_connect = if let Some(backoff_until) = ncp.backoff_until() {
                backoff_until <= Instant::now()
            } else {
                true
            };
            if should_connect && ncp.try_connect().is_ok() {
                self.out_queue
                    .push_back(PeerManagerOut::Connect(PeerIdentity::PeerId(peer_id)))
            }
        }
    }
}

impl<S: PeersState> PeerManagerRequestsBehavior for PeerManager<S> {
    fn on_add_peer(&mut self, peer_id: PeerIdentity) {
        self.state.try_add_peer(peer_id, false, false);
    }

    fn on_add_reserved_peer(&mut self, peer_id: PeerIdentity) {
        self.state.try_add_peer(peer_id, true, false);
    }

    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let unkown_peers = self.state.set_reserved_peers(peers);
        for pid in unkown_peers {
            self.state.try_add_peer(PeerIdentity::PeerId(pid), true, false);
        }
    }

    fn on_report_peer(&mut self, peer_id: PeerId, adjustment: ReputationChange) {
        match self.state.peer(&peer_id) {
            Some(peer) => {
                peer.adjust_reputation(adjustment);
            }
            None => {} // warn
        }
    }

    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: oneshot::Sender<Reputation>) {
        match self.state.peer(&peer_id) {
            Some(peer) => {
                let reputation = peer.get_reputation();
                let _ = response.send(reputation);
            }
            None => {} // warn
        }
    }

    fn on_set_peer_protocols(&mut self, peer_id: PeerId, protocols: Vec<ProtocolId>) {
        match self.state.peer(&peer_id) {
            Some(mut peer) => {
                peer.set_protocols(protocols);
            }
            None => {} // warn
        }
    }
}

impl<S: PeersState> PeerManagerNotificationsBehavior for PeerManager<S> {
    fn on_incoming_connection(&mut self, peer_id: PeerId, conn_id: ConnectionId) {
        match self.state.peer(&peer_id) {
            Some(PeerInState::NotConnected(ncp)) => {
                if ncp.get_reputation() >= self.conf.min_reputation && ncp.try_accept_connection().is_ok() {
                    self.out_queue.push_back(PeerManagerOut::Accept(peer_id, conn_id));
                } else {
                    self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                }
            }
            Some(PeerInState::Connected(_)) => {
                self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
            }
            None => {
                if let Some(ncp) = self
                    .state
                    .try_add_peer(PeerIdentity::PeerId(peer_id), false, false)
                {
                    if ncp.try_accept_connection().is_ok() {
                        self.out_queue.push_back(PeerManagerOut::Accept(peer_id, conn_id));
                    } else {
                        self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                    }
                } else {
                    self.out_queue.push_back(PeerManagerOut::Reject(peer_id, conn_id));
                }
            }
        }
    }

    fn on_connection_established(&mut self, peer_id: PeerId, _conn_id: ConnectionId) {
        if let Some(PeerInState::Connected(mut cp)) = self.state.peer(&peer_id) {
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
                    ConnectionLossReason::Reset(err) => {
                        match err {
                            ConnHandlerError::SyncChannelExhausted => {
                                // todo: DEV-385: the peer is too slow, adjust reputation.
                            }
                        }
                    }
                    ConnectionLossReason::Unknown => {}
                }
            }
            Some(PeerInState::NotConnected(_)) => {} // warn
            None => {}                               // warn
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

            if Future::poll(Pin::new(&mut self.next_conn_alloc), cx).is_ready() {
                if self.state.is_bootstrapped() {
                    todo!()
                } else {
                    self.connect_reserved();
                    self.connect_best();
                }
                self.next_conn_alloc = Delay::new(self.conf.periodic_conn_interval)
            }

            if let Poll::Ready(Some(notif)) = Stream::poll_next(Pin::new(&mut self.mailbox), cx) {
                match notif {
                    PeerManagerIn::Notification(notification) => match notification {
                        PeerEvent::IncomingConnection(pid, conn_id) => {
                            self.on_incoming_connection(pid, conn_id)
                        }
                        PeerEvent::ConnectionEstablished(pid, conn_id) => {
                            self.on_incoming_connection(pid, conn_id)
                        }
                        PeerEvent::ConnectionLost(pid, reason) => self.on_connection_lost(pid, reason),
                        PeerEvent::ForceEnabled(pid, protocol_id) => {
                            self.on_force_enabled(pid, protocol_id);
                        }
                    },
                    PeerManagerIn::Request(req) => match req {
                        PeerManagerRequest::AddPeer(pid) => self.on_add_peer(pid),
                        PeerManagerRequest::ReportPeer(pid, adjustment) => {
                            self.on_report_peer(pid, adjustment)
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

            // Allocate protocol substreams according to defined policies.
            for (prot, policy) in self.conf.protocols_allocation.clone().iter() {
                if let Some(enabled_peers) = self.state.get_enabled_peers(prot) {
                    let cond = match policy {
                        ProtocolAllocationPolicy::Bounded(max_conn_percent) => {
                            enabled_peers.len() / self.state.num_connected_peers() < *max_conn_percent / 100
                        }
                        ProtocolAllocationPolicy::Max => {
                            enabled_peers.len() < self.state.num_connected_peers()
                        }
                        ProtocolAllocationPolicy::Zero => false,
                    };
                    if cond {
                        if let Some(candidate) = self.state.peek_best(Some(|pid: &PeerId, pi: &PeerInfo| {
                            !enabled_peers.contains(pid) && pi.supports(&prot).unwrap_or(false)
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

            return Poll::Pending;
        }
    }
}
