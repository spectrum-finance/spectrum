use crate::peer::data::{ConnectionDirection, ConnectionLossReason, ReputationChange};
use crate::peer::peers_state::{NotConnectedPeer, PeerInState, PeersState};
use crate::peer::types::{IncomingIndex, Reputation};
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::channel::oneshot;
use futures::channel::oneshot::Receiver;
use libp2p::PeerId;
use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::Sender;

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
    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: Sender<Reputation>);
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
    min_reputation: Reputation
}

pub struct PeerManager<S: PeersState> {
    state: S,
    conf: PeerManagerConfig,
    notifications_recv: UnboundedReceiver<InNotification>,
    requests_recv: UnboundedReceiver<InRequest>,
    out_queue: VecDeque<OutCommand>,
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
                peer.adjust_peer_reputation(adjustment);
            }
            None => {} // warn
        }
    }

    fn on_get_peer_reputation(&mut self, peer_id: PeerId, response: Sender<Reputation>) {
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
            Some(PeerInState::NotConnected(ncp))
                if (ncp.get_reputation() >= self.conf.min_reputation) => {
                if let Err(ncp) = ncp.try_accept_connection() {
                    ncp.reg_conn_attempt();
                    self.out_queue.push_back(OutCommand::Reject(index));
                } else {
                    self.out_queue.push_back(OutCommand::Accept(index));
                }
            }
            Some(PeerInState::NotConnected(ncp)) => {
                ncp.reg_conn_attempt();
                self.out_queue.push_back(OutCommand::Reject(index));
            }
            Some(PeerInState::Connected(cp)) => {
                match cp.get_conn_direction() {
                    ConnectionDirection::Outgoing(_) => {}// todo: probably simultaneous connection attempts. Resolve conflict.
                    ConnectionDirection::Incoming => {} // warn
                }
            }
            None => {
                if let Some(ncp) = self.state.try_add_peer(peer_id, false) {
                    if let Err(ncp) = ncp.try_accept_connection() {
                        ncp.reg_conn_attempt();
                        self.out_queue.push_back(OutCommand::Reject(index));
                    } else {
                        self.out_queue.push_back(OutCommand::Accept(index));
                    }
                } else {
                    self.out_queue.push_back(OutCommand::Reject(index));
                }
            }

        }
    }

    fn on_connection_lost(&mut self, peer_id: PeerId, reason: ConnectionLossReason) {
        todo!()
    }
}
