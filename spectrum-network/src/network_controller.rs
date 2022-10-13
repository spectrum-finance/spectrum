use crate::peer_conn_handler::message_sink::MessageSink;
use crate::peer_conn_handler::{
    ConnHandlerIn, ConnHandlerOut, PartialPeerConnHandler, PeerConnHandlerConf,
};
use crate::peer_manager::{PeerManagerNotifications, Peers};
use crate::protocol::upgrade::ProtocolTag;
use crate::protocol::ProtocolConfig;
use crate::protocol_handler::ProtocolHandler;
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use libp2p::core::connection::ConnectionId;

use libp2p::core::ConnectedPoint;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters};
use libp2p::{Multiaddr, PeerId};
use log::trace;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use crate::peer_manager::data::ReputationChange;
use std::task::{Context, Poll};

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
pub enum NetworkControllerOut {
    Message {
        peer_id: PeerId,
        protocol_tag: ProtocolTag,
        content: RawMessage,
    },
}

pub struct NetworkController<TPeers, THandler> {
    conn_handler_conf: PeerConnHandlerConf,
    supported_protocols: HashMap<ProtocolId, (ProtocolConfig, THandler)>,
    peer_manager: TPeers,
    enabled_peers: HashMap<PeerId, ConnectedPeer<THandler>>,
    pending_actions: VecDeque<NetworkBehaviourAction<NetworkControllerOut, PartialPeerConnHandler>>,
}

// todo: implement NotEnabled => PendingEnable
impl<TPeers, THandler> NetworkBehaviour for NetworkController<TPeers, THandler>
where
    TPeers: Peers + PeerManagerNotifications + 'static,
    THandler: ProtocolHandler + Clone + 'static,
{
    type ConnectionHandler = PartialPeerConnHandler;
    type OutEvent = NetworkControllerOut;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        PartialPeerConnHandler::new(
            self.conn_handler_conf.clone(),
            self.supported_protocols
                .values()
                .cloned()
                .map(|(conf, _)| conf)
                .collect(),
        )
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
            Entry::Occupied(mut entry) => match entry.get() {
                ConnectedPeer::PendingConnect => {
                    entry.insert(ConnectedPeer::Connected {
                        conn_id: *conn_id,
                        enabled_protocols: HashMap::new(),
                    });
                }
                ConnectedPeer::Connected { .. }
                | ConnectedPeer::PendingDisconnect(..)
                | ConnectedPeer::PendingApprove(..) => {}
            },
            Entry::Vacant(entry) => {
                self.peer_manager.incoming_connection(*peer_id, *conn_id);
                entry.insert(ConnectedPeer::PendingApprove(*conn_id));
            }
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
                                if let Err(err) = handler.protocol_enabled(
                                    peer_id,
                                    protocol_ver,
                                    handshake,
                                    out_channel.clone(),
                                ) {
                                    trace!(
                                        "Failed to enable protocol {:?} with peer {:?} due to {:?}",
                                        protocol_id,
                                        peer_id,
                                        err
                                    );
                                    self.peer_manager
                                        .report_peer(peer_id, ReputationChange::MalformedMessage);
                                    self.pending_actions.push_back(
                                        NetworkBehaviourAction::NotifyHandler {
                                            peer_id,
                                            handler: NotifyHandler::One(connection),
                                            event: ConnHandlerIn::Close(protocol_id),
                                        },
                                    )
                                } else {
                                    let enabled_protocol = EnabledProtocol::Enabled {
                                        ver: protocol_ver,
                                        sink: out_channel,
                                    };
                                    entry.insert((enabled_protocol, handler.clone()));
                                }
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
                            if let Err(err) = prot_handler.protocol_requested(
                                peer_id,
                                protocol_tag.protocol_ver(),
                                handshake,
                            ) {
                                trace!(
                                    "Peer {:?} failed his attempt to open protocol {:?} due to {:?}",
                                    peer_id,
                                    protocol_id,
                                    err
                                );
                                self.peer_manager
                                    .report_peer(peer_id, ReputationChange::MalformedMessage);
                                self.pending_actions.push_back(
                                    NetworkBehaviourAction::NotifyHandler {
                                        peer_id,
                                        handler: NotifyHandler::One(connection),
                                        event: ConnHandlerIn::Close(protocol_id),
                                    },
                                )
                            };
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
                            if let Err(err) = prot_handler.incoming_msg(
                                peer_id,
                                protocol_tag.protocol_ver(),
                                content,
                            ) {
                                trace!(
                                    "Failed to handle msg from peer {:?}, protocol {:?}",
                                    peer_id,
                                    protocol_id
                                );
                                self.peer_manager
                                    .report_peer(peer_id, ReputationChange::MalformedMessage);
                                self.pending_actions.push_back(
                                    NetworkBehaviourAction::NotifyHandler {
                                        peer_id,
                                        handler: NotifyHandler::One(connection),
                                        event: ConnHandlerIn::Close(protocol_id),
                                    },
                                )
                            };
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
        // 2. Poll for instructions from the PM.
        todo!()
    }
}
