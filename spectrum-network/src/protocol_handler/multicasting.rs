use std::collections::{HashSet, VecDeque};
use std::task::{Context, Poll};

use either::{Either, Right};
use libp2p::Multiaddr;
use libp2p_identity::PeerId;

use algebra_core::CommutativeSemigroup;
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::multicasting::overlay::TreeOverlay;
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};

mod overlay;

pub struct TreeBasedMulticasting<S, P> {
    statement: Option<S>,
    public_data: P,
    overlay: TreeOverlay,
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, S>>,
}

impl<S, P> TemporalProtocolStage<VoidMessage, S, S> for TreeBasedMulticasting<S, P>
where
    S: CommutativeSemigroup + VerifiableAgainst<P> + Clone,
{
    fn inject_message(&mut self, peer_id: PeerId, content: S) {
        if self.overlay.parent_nodes.contains(&peer_id) {
            if content.verify(&self.public_data) {
                if let Some(stmt) = self.statement.take() {
                    let _ = self.statement.insert(stmt.combine(&content));
                }
            } else {
                self.outbox
                    .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(
                        peer_id,
                    )))
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Either<ProtocolBehaviourOut<VoidMessage, S>, S>> {
        if let Some(stmt) = self.statement.take() {
            for (peer, addr) in &self.overlay.child_nodes {
                self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                    NetworkAction::SendOneShotMessage {
                        peer: *peer,
                        addr_hint: addr.clone(),
                        use_version: Default::default(),
                        message: stmt.clone(),
                    },
                ))
            }
            return Poll::Ready(Right(stmt));
        }
        return Poll::Pending;
    }
}
