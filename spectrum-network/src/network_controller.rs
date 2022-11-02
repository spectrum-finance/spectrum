use crate::peer_conn_handler::message_sink::MessageSink;
use crate::peer_conn_handler::{ConnHandlerIn, ConnHandlerOut, PartialPeerConnHandler, PeerConnHandlerConf};
use crate::peer_manager::{PeerActions, PeerEvents, PeerManagerOut};
use crate::protocol::{ProtocolConfig, SYNC_PROTOCOL_ID};
use crate::protocol_api::ProtocolEvents;
use crate::types::{ProtocolId, ProtocolVer};

use libp2p::core::connection::ConnectionId;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{
    CloseConnection, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use libp2p::{Multiaddr, PeerId};

use futures::channel::mpsc;
use log::trace;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::peer_manager::data::ConnectionLossReason;
use crate::protocol_upgrade::handshake::PolyVerHandshakeSpec;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::Stream;

/// States of an enabled protocol.
pub enum EnabledProtocol {
    /// Bi-directional communication on this protocol is enabled.
    Enabled { ver: ProtocolVer, sink: MessageSink },
    /// Substreams for this protocol are requested by peer.
    PendingApprove,
    /// Substreams for this protocol are requested.
    PendingEnable,
    /// Waiting for the substreams to be closed.
    PendingDisable,
}

pub enum ConnectedPeer<THandler> {
    /// We are connected to this peer.
    Connected {
        conn_id: ConnectionId,
        enabled_protocols: HashMap<ProtocolId, (EnabledProtocol, THandler)>,
    },
    /// The peer is connected but not approved by PM yet.
    PendingApprove(ConnectionId),
    /// PM requested that we should connect to this peer.
    PendingConnect,
    /// PM requested that we should disconnect this peer.
    PendingDisconnect(ConnectionId),
}

#[derive(Debug)]
pub enum NetworkControllerOut {}

pub enum NetworkControllerIn {
    /// A directive to enable the specified protocol with the specified peer.
    EnableProtocol {
        /// The desired protocol.
        protocol: ProtocolId,
        /// A specific peer we should start the protocol with.
        peer: PeerId,
        /// A handshake to send to the peer upon negotiation of protocol substream.
        handshake: PolyVerHandshakeSpec,
    },
    /// A directive to update the set of protocols supported by the specified peer.
    UpdatePeerProtocols {
        peer: PeerId,
        protocols: Vec<ProtocolId>,
    },
}

pub trait NetworkAPI {
    fn enable_protocol(&self, protocol: ProtocolId, peer: PeerId, handshake: PolyVerHandshakeSpec);
    fn update_peer_protocols(&self, peer: PeerId, protocols: Vec<ProtocolId>);
}

#[derive(Clone)]
pub struct NetworkMailbox {
    mailbox_snd: UnboundedSender<NetworkControllerIn>,
}

impl NetworkAPI for NetworkMailbox {
    fn enable_protocol(&self, protocol: ProtocolId, peer: PeerId, handshake: PolyVerHandshakeSpec) {
        let _ = self
            .mailbox_snd
            .unbounded_send(NetworkControllerIn::EnableProtocol {
                protocol,
                peer,
                handshake,
            });
    }
    fn update_peer_protocols(&self, peer: PeerId, protocols: Vec<ProtocolId>) {
        let _ = self
            .mailbox_snd
            .unbounded_send(NetworkControllerIn::UpdatePeerProtocols { peer, protocols });
    }
}

pub struct NetworkController<TPeers, TPeerManager, THandler> {
    conn_handler_conf: PeerConnHandlerConf,
    /// Sync protocol is always enabled
    sync_protocol: (ProtocolConfig, THandler),
    /// Other supported protocols
    supported_protocols: HashMap<ProtocolId, (ProtocolConfig, THandler)>,
    /// PeerManager API
    peers: TPeers,
    /// PeerManager stream itself
    peer_manager: TPeerManager,
    enabled_peers: HashMap<PeerId, ConnectedPeer<THandler>>,
    requests_recv: UnboundedReceiver<NetworkControllerIn>,
    pending_actions: VecDeque<NetworkBehaviourAction<NetworkControllerOut, PartialPeerConnHandler>>,
}

impl<TPeers, TPeerManager, THandler> NetworkController<TPeers, TPeerManager, THandler>
where
    THandler: Clone,
{
    fn init_handler(&self) -> PartialPeerConnHandler {
        PartialPeerConnHandler::new(
            self.conn_handler_conf.clone(),
            vec![(SYNC_PROTOCOL_ID, self.sync_protocol.0.clone())]
                .into_iter()
                .chain(
                    self.supported_protocols
                        .iter()
                        .clone()
                        .map(|(prot_id, (conf, _))| (*prot_id, conf.clone())),
                )
                .collect::<Vec<_>>(),
        )
    }
}

pub fn make<TPeers, TPeerManager, THandler>(
    conn_handler_conf: PeerConnHandlerConf,
    sync_protocol: (ProtocolConfig, THandler),
    supported_protocols: HashMap<ProtocolId, (ProtocolConfig, THandler)>,
    peers: TPeers,
    peer_manager: TPeerManager,
) -> (NetworkController<TPeers, TPeerManager, THandler>, NetworkMailbox) {
    let (requests_snd, requests_recv) = mpsc::unbounded::<NetworkControllerIn>();
    let network_controller = NetworkController {
        conn_handler_conf,
        sync_protocol,
        supported_protocols,
        peers,
        peer_manager,
        enabled_peers: HashMap::new(),
        requests_recv,
        pending_actions: VecDeque::new(),
    };
    let network_api = NetworkMailbox {
        mailbox_snd: requests_snd,
    };
    (network_controller, network_api)
}

// todo: implement initial handshake
impl<TPeers, TPeerManager, THandler> NetworkBehaviour for NetworkController<TPeers, TPeerManager, THandler>
where
    TPeers: PeerEvents + PeerActions + 'static,
    TPeerManager: Stream<Item = PeerManagerOut> + Unpin + 'static,
    THandler: ProtocolEvents + Clone + 'static,
{
    type ConnectionHandler = PartialPeerConnHandler;
    type OutEvent = NetworkControllerOut;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        self.init_handler()
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        conn_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        match self.enabled_peers.entry(*peer_id) {
            Entry::Occupied(mut peer_entry) => match peer_entry.get() {
                ConnectedPeer::PendingConnect => {
                    self.peers.connection_established(*peer_id, *conn_id); // confirm connection
                    peer_entry.insert(ConnectedPeer::Connected {
                        conn_id: *conn_id,
                        enabled_protocols: HashMap::new(),
                    });
                    // Immediately request sync protocol.
                    self.sync_protocol.1.protocol_requested_local(*peer_id);
                }
                ConnectedPeer::Connected { .. }
                | ConnectedPeer::PendingDisconnect(..)
                | ConnectedPeer::PendingApprove(..) => {
                    self.pending_actions
                        .push_back(NetworkBehaviourAction::CloseConnection {
                            peer_id: *peer_id,
                            connection: CloseConnection::One(*conn_id),
                        })
                }
            },
            Entry::Vacant(entry) => {
                self.peers.incoming_connection(*peer_id, *conn_id);
                entry.insert(ConnectedPeer::PendingApprove(*conn_id));
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _conn_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
        match self.enabled_peers.entry(*peer_id) {
            Entry::Occupied(peer_entry) => match peer_entry.get() {
                ConnectedPeer::Connected { .. } | ConnectedPeer::PendingDisconnect(..) => {
                    if let Some(err) = handler.get_fault() {
                        self.peers
                            .connection_lost(*peer_id, ConnectionLossReason::Reset(err));
                    } else {
                        self.peers
                            .connection_lost(*peer_id, ConnectionLossReason::ResetByPeer);
                    }
                    peer_entry.remove();
                }
                // todo: is it possible in case of simultaneous connection?
                ConnectedPeer::PendingConnect | ConnectedPeer::PendingApprove(..) => {}
            },
            Entry::Vacant(_) => {}
        }
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: ConnHandlerOut) {
        match event {
            ConnHandlerOut::Opened {
                protocol_tag,
                handshake,
                out_channel,
            } => {
                if let Some(ConnectedPeer::Connected {
                    enabled_protocols, ..
                }) = self.enabled_peers.get_mut(&peer_id)
                {
                    let protocol_id = protocol_tag.protocol_id();
                    let protocol_ver = protocol_tag.protocol_ver();
                    match enabled_protocols.entry(protocol_id) {
                        Entry::Occupied(mut entry) => {
                            if let (EnabledProtocol::PendingEnable, handler) = entry.get() {
                                handler.protocol_enabled(
                                    peer_id,
                                    protocol_ver,
                                    handshake,
                                    out_channel.clone(),
                                );
                                let enabled_protocol = EnabledProtocol::Enabled {
                                    ver: protocol_ver,
                                    sink: out_channel,
                                };
                                entry.insert((enabled_protocol, handler.clone()));
                            }
                        }
                        Entry::Vacant(entry) => {
                            trace!("Unknown protocol was opened {:?}", entry.key())
                        }
                    }
                }
            }
            ConnHandlerOut::OpenedByPeer {
                protocol_tag,
                handshake,
            } => {
                if let Some(ConnectedPeer::Connected {
                    enabled_protocols, ..
                }) = self.enabled_peers.get_mut(&peer_id)
                {
                    let protocol_id = protocol_tag.protocol_id();
                    let (_, prot_handler) = self.supported_protocols.get(&protocol_id).unwrap();
                    match enabled_protocols.entry(protocol_id) {
                        Entry::Vacant(entry) => {
                            entry.insert((EnabledProtocol::PendingApprove, prot_handler.clone()));
                            prot_handler.protocol_requested(peer_id, protocol_tag.protocol_ver(), handshake);
                        }
                        Entry::Occupied(_) => {
                            trace!(
                                "Peer {:?} opened already enabled protocol {:?}",
                                peer_id,
                                protocol_id
                            );
                            self.pending_actions
                                .push_back(NetworkBehaviourAction::NotifyHandler {
                                    peer_id,
                                    handler: NotifyHandler::One(connection),
                                    event: ConnHandlerIn::Close(protocol_id),
                                })
                        }
                    }
                }
            }
            ConnHandlerOut::ClosedByPeer(protocol_id)
            | ConnHandlerOut::RefusedToOpen(protocol_id)
            | ConnHandlerOut::Closed(protocol_id) => {
                if let Some(ConnectedPeer::Connected {
                    enabled_protocols, ..
                }) = self.enabled_peers.get_mut(&peer_id)
                {
                    match enabled_protocols.entry(protocol_id) {
                        Entry::Occupied(entry) => {
                            trace!(
                                "Peer {:?} closed the substream for protocol {:?}",
                                peer_id,
                                protocol_id
                            );
                            entry.remove();
                        }
                        Entry::Vacant(_) => {}
                    }
                }
            }
            ConnHandlerOut::Message {
                protocol_tag,
                content,
            } => {
                if let Some(ConnectedPeer::Connected {
                    enabled_protocols, ..
                }) = self.enabled_peers.get_mut(&peer_id)
                {
                    let protocol_id = protocol_tag.protocol_id();
                    match enabled_protocols.get(&protocol_id) {
                        Some((_, prot_handler)) => {
                            prot_handler.incoming_msg(peer_id, protocol_tag.protocol_ver(), content);
                        }
                        None => {} // todo: probably possible?
                    };
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // 1. Try to return a pending action.
        if let Some(action) = self.pending_actions.pop_front() {
            return Poll::Ready(action);
        };
        loop {
            // 2. Poll for instructions from PM.
            match Stream::poll_next(Pin::new(&mut self.peer_manager), cx) {
                Poll::Ready(Some(PeerManagerOut::Connect(pid))) => {
                    let handler = self.init_handler();
                    match self.enabled_peers.entry(pid) {
                        Entry::Occupied(_) => {}
                        Entry::Vacant(peer_entry) => {
                            peer_entry.insert(ConnectedPeer::PendingConnect);
                            self.pending_actions.push_back(NetworkBehaviourAction::Dial {
                                opts: pid.into(),
                                handler,
                            })
                        }
                    }
                }
                Poll::Ready(Some(PeerManagerOut::Drop(peer_id))) => {
                    if let Some(ConnectedPeer::Connected {
                        conn_id,
                        enabled_protocols,
                    }) = self.enabled_peers.get_mut(&peer_id)
                    {
                        let mut protocols = Vec::new();
                        for prot_id in enabled_protocols.keys() {
                            protocols.push(*prot_id);
                        }
                        for prot_id in protocols {
                            match enabled_protocols.entry(prot_id) {
                                Entry::Occupied(mut prot) => {
                                    let (st, han) = prot.get();
                                    match st {
                                        EnabledProtocol::Enabled { .. }
                                        | EnabledProtocol::PendingEnable
                                        | EnabledProtocol::PendingApprove => {
                                            prot.insert((EnabledProtocol::PendingDisable, han.clone()));
                                            self.pending_actions.push_back(
                                                NetworkBehaviourAction::NotifyHandler {
                                                    peer_id,
                                                    handler: NotifyHandler::One(*conn_id),
                                                    event: ConnHandlerIn::Close(prot_id),
                                                },
                                            )
                                        }
                                        EnabledProtocol::PendingDisable => {}
                                    }
                                }
                                Entry::Vacant(_) => {}
                            }
                        }
                    }
                }
                Poll::Ready(Some(PeerManagerOut::Accept(pid, cid))) => match self.enabled_peers.entry(pid) {
                    Entry::Occupied(mut peer) => {
                        if let ConnectedPeer::PendingApprove(_) = peer.get() {
                            peer.insert(ConnectedPeer::Connected {
                                conn_id: cid,
                                enabled_protocols: HashMap::new(),
                            });
                        }
                    }
                    Entry::Vacant(_) => {}
                },
                Poll::Ready(Some(PeerManagerOut::Reject(pid, _))) => match self.enabled_peers.entry(pid) {
                    Entry::Occupied(peer) => {
                        if let ConnectedPeer::PendingApprove(_) = peer.get() {
                            peer.remove();
                        }
                    }
                    Entry::Vacant(_) => {}
                },
                Poll::Ready(Some(PeerManagerOut::StartProtocol(protocol, pid))) => {
                    match self.enabled_peers.entry(pid) {
                        Entry::Occupied(mut peer) => {
                            let peer = peer.get_mut();
                            match peer {
                                ConnectedPeer::Connected {
                                    enabled_protocols, ..
                                } => {
                                    let (_, prot_handler) = self.supported_protocols.get(&protocol).unwrap();
                                    match enabled_protocols.entry(protocol) {
                                        Entry::Occupied(_) => trace!(
                                            "PM requested already enabled protocol {:?} with peer {:?}",
                                            protocol,
                                            pid
                                        ),
                                        Entry::Vacant(protocol_entry) => {
                                            protocol_entry.insert((
                                                EnabledProtocol::PendingEnable,
                                                prot_handler.clone(),
                                            ));
                                            prot_handler.protocol_requested_local(pid);
                                        }
                                    };
                                }
                                ConnectedPeer::PendingConnect
                                | ConnectedPeer::PendingApprove(_)
                                | ConnectedPeer::PendingDisconnect(_) => {}
                            }
                        }
                        Entry::Vacant(_) => {}
                    }
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        // 3. Poll commands from protocol handlers.
        if let Poll::Ready(Some(input)) = Stream::poll_next(Pin::new(&mut self.requests_recv), cx) {
            match input {
                NetworkControllerIn::UpdatePeerProtocols { peer, protocols } => {
                    self.peers.set_peer_protocols(peer, protocols);
                }
                NetworkControllerIn::EnableProtocol {
                    peer: peer_id,
                    protocol: protocol_id,
                    handshake,
                } => {
                    if let Some(ConnectedPeer::Connected {
                        conn_id,
                        enabled_protocols,
                    }) = self.enabled_peers.get_mut(&peer_id)
                    {
                        let (_, prot_handler) = self.supported_protocols.get(&protocol_id).unwrap();
                        match enabled_protocols.entry(protocol_id) {
                            Entry::Occupied(protocol_entry) => match protocol_entry.get() {
                                // Protocol Handler approves either outbound or inbound protocol request.
                                (EnabledProtocol::PendingEnable | EnabledProtocol::PendingApprove, _) => self
                                    .pending_actions
                                    .push_back(NetworkBehaviourAction::NotifyHandler {
                                        peer_id,
                                        handler: NotifyHandler::One(*conn_id),
                                        event: ConnHandlerIn::Open {
                                            protocol_id,
                                            handshake,
                                        },
                                    }),
                                (EnabledProtocol::Enabled { .. } | EnabledProtocol::PendingDisable, _) => {}
                            },
                            // Also, Protocol Handler can request a substream on its own.
                            Entry::Vacant(protocol_entry) => {
                                trace!(
                                    "Handler requested to open protocol {:?} with peer {:?}",
                                    protocol_id,
                                    peer_id
                                );
                                protocol_entry.insert((EnabledProtocol::PendingEnable, prot_handler.clone()));
                                self.peers.force_enabled(peer_id, protocol_id); // notify PM
                                self.pending_actions
                                    .push_back(NetworkBehaviourAction::NotifyHandler {
                                        peer_id,
                                        handler: NotifyHandler::One(*conn_id),
                                        event: ConnHandlerIn::Open {
                                            protocol_id,
                                            handshake,
                                        },
                                    });
                            }
                        }
                    }
                }
            }
        }

        Poll::Pending
    }
}
