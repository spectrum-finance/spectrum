use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::FuturesOrdered;
use futures::Stream;
use log::error;

use spectrum_ledger::ledger_view::history::HistoryAsync;

use crate::protocol::DIFFUSION_PROTOCOL_ID;
use crate::protocol_handler::diffusion::message::{DiffusionHandshake, DiffusionMessage, DiffusionSpec};
use crate::protocol_handler::{ProtocolBehaviour, ProtocolBehaviourOut, ProtocolSpec};
use crate::types::ProtocolId;

pub mod message;
pub(super) mod types;

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Debug, derive_more::Display)]
pub enum DiffusionBehaviorError {
    ModifierNotFound,
    OperationCancelled,
}

type DiffusionTask =
    Pin<Box<dyn Future<Output = Result<DiffusionBehaviourOut, DiffusionBehaviorError>> + Send>>;

pub struct DiffusionBehaviour<THistory> {
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: FuturesOrdered<DiffusionTask>,
    history: THistory,
}

impl<THistory> ProtocolBehaviour for DiffusionBehaviour<THistory>
where
    THistory: HistoryAsync,
{
    type TProto = DiffusionSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        DIFFUSION_PROTOCOL_ID
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(Ok(out))) => {
                    self.outbox.push_back(out);
                    continue;
                }
                Poll::Ready(Some(Err(err))) => {
                    error!("An error occured: {}", err);
                    continue;
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Some(out));
        }
        Poll::Pending
    }
}
