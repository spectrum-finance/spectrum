use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;

use futures::stream::FuturesOrdered;

use crate::protocol_handler::diffusion::message::{DiffusionHandshake, DiffusionMessage};
use crate::protocol_handler::ProtocolBehaviourOut;

pub mod message;
pub(super) mod types;

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Debug, derive_more::Display)]
pub enum DiffusionBehaviorError {
    ModifierNotFound,
    OperationCancelled,
}

type DiscoveryTask =
    Pin<Box<dyn Future<Output = Result<DiffusionBehaviourOut, DiffusionBehaviorError>> + Send>>;

pub struct DiffusionBehaviour<THistory> {
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: FuturesOrdered<DiscoveryTask>,
    history: THistory,
}
