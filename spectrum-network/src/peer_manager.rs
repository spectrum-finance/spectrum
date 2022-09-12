pub mod data;
pub mod peer_store;
pub mod peers_state;

use crate::peer_manager::data::{ConnectionLossReason, ReputationChange};
use crate::peer_manager::peers_state::{PeerInState, PeerStateFilter, PeersState};
use crate::types::{IncomingIndex, Reputation};
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot;
use futures::channel::oneshot::Receiver;
use futures::Stream;
use libp2p::PeerId;
use std::collections::{HashSet, VecDeque};
use std::ops::Add;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Peer Manager output commands.
#[derive(Debug, PartialEq)]
pub enum OutCommand {
    /// Request to open a connection to the given peer. From the point of view of the PSM, we are
    /// immediately connected.
    Connect(PeerId),

    /// Drop the connection to the given peer, or cancel the connection attempt after a `Connect`.
    Drop(PeerId),

    /// Equivalent to `Connect` for the peer corresponding to this incoming index.
    Accept(IncomingIndex),

    /// Equivalent to `Drop` for the peer corresponding to this incoming index.
    Reject(IncomingIndex),
}

/// Peer Manager inputs.
#[derive(Debug)]
pub enum InRequest {
    AddPeer(PeerId),
    AddReservedPeer(PeerId),
    SetReservedPeers(HashSet<PeerId>),
    ReportPeer(PeerId, ReputationChange),
    GetPeerReputation(PeerId, oneshot::Sender<Reputation>),
}

/// Events Peer Manager reacts to.
#[derive(Debug)]
pub enum InNotification {
    IncomingConnection(PeerId, IncomingIndex),
    ConnectionLost(PeerId, ConnectionLossReason),
}

pub enum Input {
    Notification(InNotification),
    Request(InRequest),
}

/// Async API to PeerManager.
pub trait Peers {
    fn add_peer(&mut self, peer_id: PeerId);
    fn add_reserved_peer(&mut self, peer_id: PeerId);
    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation>;
}

/// Async API to PeerManager notifications.
trait PeerManagerNotifications {
    fn incoming_connection(&mut self, peer_id: PeerId, index: IncomingIndex);
    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
}

trait PeerManagerRequestsBehavior {
    fn on_add_peer(&mut self, peer_id: PeerId);
    fn on_add_reserved_peer(&mut self, peer_id: PeerId);
    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>);
    fn on_report_peer(&mut self, peer_id: PeerId, change: ReputationChange);
    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: oneshot::Sender<Reputation>);
}

trait PeerManagerNotificationsBehavior {
    fn on_incoming_connection(&mut self, peer_id: PeerId, index: IncomingIndex);
    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason);
}

pub struct PeersLive {
    requests_snd: UnboundedSender<InRequest>,
}

impl Peers for PeersLive {
    fn add_peer(&mut self, peer_id: PeerId) {
        let _ = self
            .requests_snd
            .unbounded_send(InRequest::AddPeer(peer_id));
    }

    fn add_reserved_peer(&mut self, peer_id: PeerId) {
        let _ = self
            .requests_snd
            .unbounded_send(InRequest::AddReservedPeer(peer_id));
    }

    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let _ = self
            .requests_snd
            .unbounded_send(InRequest::SetReservedPeers(peers));
    }

    fn report_peer(&mut self, peer_id: PeerId, change: ReputationChange) {
        let _ = self
            .requests_snd
            .unbounded_send(InRequest::ReportPeer(peer_id, change));
    }

    fn get_peer_reputation(&mut self, peer_id: PeerId) -> Receiver<Reputation> {
        let (sender, receiver) = oneshot::channel::<Reputation>();
        let _ = self
            .requests_snd
            .unbounded_send(InRequest::GetPeerReputation(peer_id, sender));
        receiver
    }
}

pub struct PeerManagerNotificationsLive {
    notifications_snd: UnboundedSender<InNotification>,
}

impl PeerManagerNotifications for PeerManagerNotificationsLive {
    fn incoming_connection(&mut self, peer_id: PeerId, index: IncomingIndex) {
        let _ = self
            .notifications_snd
            .unbounded_send(InNotification::IncomingConnection(peer_id, index));
    }

    fn connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        let _ = self
            .notifications_snd
            .unbounded_send(InNotification::ConnectionLost(peer_id, reason));
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PeerManagerConfig {
    min_reputation: Reputation,
    conn_reset_outbound_backoff: Duration,
    periodic_conn_interval: Duration,
}

pub struct PeerManager<PState> {
    state: PState,
    conf: PeerManagerConfig,
    notifications_recv: UnboundedReceiver<InNotification>,
    requests_recv: UnboundedReceiver<InRequest>,
    out_queue: VecDeque<OutCommand>,
    next_conn_alloc_at: Instant,
}

impl<S: PeersState> PeerManager<S> {
    /// Connect to reserved peers we are not connected yet.
    pub fn connect_reserved(&mut self) {
        let peers = self
            .state
            .get_reserved_peers(Some(PeerStateFilter::NotConnected));
        for pid in peers {
            self.connect(pid)
        }
    }

    /// Connect to a best peer we are not connected yet.
    pub fn connect_best(&mut self) {
        if let Some(pid) = self.state.peek_best() {
            self.connect(pid)
        }
    }

    fn connect(&mut self, peer_id: PeerId) {
        if let Some(PeerInState::NotConnected(ncp)) = self.state.peer(&peer_id) {
            let should_connect = if let Some(backoff_until) = ncp.backoff_until() {
                backoff_until <= Instant::now()
            } else {
                true
            };
            if should_connect && ncp.try_connect().is_ok() {
                self.out_queue.push_back(OutCommand::Connect(peer_id))
            }
        }
    }
}

impl<S: PeersState> PeerManagerRequestsBehavior for PeerManager<S> {
    fn on_add_peer(&mut self, peer_id: PeerId) {
        self.state.try_add_peer(peer_id, false);
    }

    fn on_add_reserved_peer(&mut self, peer_id: PeerId) {
        self.state.try_add_peer(peer_id, true);
    }

    fn on_set_reserved_peers(&mut self, peers: HashSet<PeerId>) {
        let unkown_peers = self.state.set_reserved_peers(peers);
        for pid in unkown_peers {
            if let Some(_) = self.state.try_add_peer(pid, true) {
                let _ = self.out_queue.push_back(OutCommand::Connect(pid));
            } else {
            } // warn
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
}

impl<S: PeersState> PeerManagerNotificationsBehavior for PeerManager<S> {
    fn on_incoming_connection(&mut self, peer_id: PeerId, index: IncomingIndex) {
        match self.state.peer(&peer_id) {
            Some(PeerInState::NotConnected(ncp)) => {
                if ncp.get_reputation() >= self.conf.min_reputation
                    && ncp.try_accept_connection().is_ok()
                {
                    self.out_queue.push_back(OutCommand::Accept(index));
                } else {
                    self.out_queue.push_back(OutCommand::Reject(index));
                }
            }
            Some(PeerInState::Connected(_)) => {
                self.out_queue.push_back(OutCommand::Reject(index));
            }
            None => {
                if let Some(ncp) = self.state.try_add_peer(peer_id, false) {
                    if ncp.try_accept_connection().is_ok() {
                        self.out_queue.push_back(OutCommand::Accept(index));
                    } else {
                        self.out_queue.push_back(OutCommand::Reject(index));
                    }
                } else {
                    self.out_queue.push_back(OutCommand::Reject(index));
                }
            }
        }
    }

    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        match self.state.peer(&peer_id) {
            Some(PeerInState::Connected(cp)) => {
                let mut ncp = cp.disconnect();
                match reason {
                    ConnectionLossReason::ResetByPeer => {
                        if !ncp.is_reserved() {
                            let backoff_until =
                                Instant::now().add(self.conf.conn_reset_outbound_backoff);
                            ncp.set_backoff_until(backoff_until);
                        }
                    }
                    ConnectionLossReason::Unknown => {}
                }
            }
            Some(PeerInState::NotConnected(_)) => {} // warn
            None => {}                               // warn
        }
    }
}

impl<S: Unpin + PeersState> Stream for PeerManager<S> {
    type Item = OutCommand;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(out) = self.out_queue.pop_front() {
                return Poll::Ready(Some(out));
            }

            let now = Instant::now();
            if self.next_conn_alloc_at >= now {
                self.connect_reserved();
                self.connect_best();
                self.next_conn_alloc_at = now.add(self.conf.periodic_conn_interval);
            }

            if let Poll::Ready(Some(notif)) =
            Stream::poll_next(Pin::new(&mut self.notifications_recv), cx)
            {
                match notif {
                    InNotification::IncomingConnection(pid, index) => {
                        self.on_incoming_connection(pid, index)
                    }
                    InNotification::ConnectionLost(pid, reason) => {
                        self.on_connection_lost(pid, reason)
                    }
                }
            }

            if let Poll::Ready(Some(req)) = Stream::poll_next(Pin::new(&mut self.requests_recv), cx)
            {
                match req {
                    InRequest::AddPeer(pid) => self.on_add_peer(pid),
                    InRequest::ReportPeer(pid, adjustment) => self.on_report_peer(pid, adjustment),
                    InRequest::AddReservedPeer(pid) => self.on_add_reserved_peer(pid),
                    InRequest::GetPeerReputation(pid, resp) => {
                        self.on_get_peer_reputation(pid, resp)
                    }
                    InRequest::SetReservedPeers(peers) => self.on_set_reserved_peers(peers),
                }
            }
        }
    }
}
