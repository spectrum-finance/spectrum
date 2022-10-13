use crate::peer_conn_handler::message_sink::MessageSink;
use crate::peer_conn_handler::{
    ConnHandlerIn, ConnHandlerOut, PartialPeerConnHandler, PeerConnHandlerConf,
};
use crate::peer_manager::PeerManagerNotifications;
use crate::protocol::upgrade::ProtocolTag;
use crate::protocol::ProtocolConfig;
use crate::routing::{Message, OutboxRouter};
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use libp2p::core::connection::ConnectionId;

use libp2p::core::ConnectedPoint;
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters};
use libp2p::{Multiaddr, PeerId};
use log::trace;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

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

pub enum ConnectedPeer {
    /// We are connected to this peer.
    Connected {
        conn_id: ConnectionId,
        enabled_protocols: HashMap<ProtocolId, EnabledProtocol>,
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

pub struct NetworkController<TPeers, TRouter> {
    conn_handler_conf: PeerConnHandlerConf,
    supported_protocols: Vec<ProtocolConfig>,
    peer_manager: TPeers,
    msg_router: TRouter,
    enabled_peers: HashMap<PeerId, ConnectedPeer>,
    pending_actions: VecDeque<NetworkBehaviourAction<NetworkControllerOut, PartialPeerConnHandler>>,
}

impl<TPeers, TRouter> NetworkBehaviour for NetworkController<TPeers, TRouter>
where
    TPeers: PeerManagerNotifications + 'static,
    TRouter: OutboxRouter + 'static,
{
    type ConnectionHandler = PartialPeerConnHandler;
    type OutEvent = NetworkControllerOut;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        PartialPeerConnHandler::new(
            self.conn_handler_conf.clone(),
            self.supported_protocols.clone(),
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
                    match enabled_protocols.entry(protocol_tag.protocol_id()) {
                        Entry::Occupied(mut entry) => {
                            if let EnabledProtocol::PendingEnable = entry.get() {
                                if let Some(hs) = handshake {
                                    // todo:
                                    self.msg_router
                                        .route(Message::new(peer_id, protocol_tag, hs));
                                };
                                entry.insert(EnabledProtocol::Enabled {
                                    ver: protocol_tag.protocol_ver(),
                                    sink: out_channel,
                                });
                            }
                        }
                        Entry::Vacant(entry) => {
                            trace!("Unknown protocol was opened {:?}", entry.key())
                        }
                    }
                }
            }
            ConnHandlerOut::OpenedByPeer(protocol_id) => {
                if let Some(ConnectedPeer::Connected {
                    enabled_protocols, ..
                }) = self.enabled_peers.get_mut(&peer_id)
                {
                    match enabled_protocols.entry(protocol_id) {
                        Entry::Vacant(entry) => {
                            entry.insert(EnabledProtocol::PendingApprove);
                            //todo: self.handlers.get(protocol_id).protocol_requested()
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
                if let Err(msg) =
                    self.msg_router
                        .route(Message::new(peer_id, protocol_tag, content))
                {
                    trace!(target: "NetworkController", "Unhandled message from {}, {:?}", peer_id, msg)
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
