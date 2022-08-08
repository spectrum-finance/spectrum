use std::task::{Context, Poll};
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive, SubstreamProtocol};
use libp2p::swarm::handler::{InboundUpgradeSend, OutboundUpgradeSend};

struct Handler {

}

impl ConnectionHandler for Handler {

    type InEvent = ();
    type OutEvent = ();
    type Error = ();
    type InboundProtocol = ();
    type OutboundProtocol = ();
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        todo!()
    }

    fn inject_fully_negotiated_inbound(&mut self, protocol: <Self::InboundProtocol as InboundUpgradeSend>::Output, info: Self::InboundOpenInfo) {
        todo!()
    }

    fn inject_fully_negotiated_outbound(&mut self, protocol: <Self::OutboundProtocol as OutboundUpgradeSend>::Output, info: Self::OutboundOpenInfo) {
        todo!()
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        todo!()
    }

    fn inject_dial_upgrade_error(&mut self, info: Self::OutboundOpenInfo, error: ConnectionHandlerUpgrErr<<Self::OutboundProtocol as OutboundUpgradeSend>::Error>) {
        todo!()
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        todo!()
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent, Self::Error>> {
        todo!()
    }
}