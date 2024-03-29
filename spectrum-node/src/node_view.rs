use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{Receiver, Sender};
use futures::{SinkExt, Stream, StreamExt};

use spectrum_consensus::block_header::validate_block_header;
use spectrum_consensus::protocol_params::ProtocolParams;
use spectrum_ledger::Modifier;
use spectrum_validation::rules::ConsensusRuleSet;
use spectrum_validation::validation::InvalidModifier;
use spectrum_view::history::{LedgerHistoryReadSync, LedgerHistoryWrite};
use spectrum_view::node_view::NodeViewWriteAsync;
use spectrum_view::state::{
    Cells, ConsensusIndexes, LedgerStateWrite, StakeDistribution, ValidatorCredentials,
};

#[derive(Clone, Debug)]
pub enum NodeViewIn {
    ApplyModifier(Modifier),
}

pub trait ErrorHandler {
    fn on_invalid_modifier(&self, err: InvalidModifier);
}

pub struct NodeView<TState, THistory, TMempool, TErrHandler, TRuleSet, TProtocol> {
    state: TState,
    history: THistory,
    mempool: TMempool,
    err_handler: TErrHandler,
    rules: TRuleSet,
    protocol: TProtocol,
    inbox: Receiver<NodeViewIn>,
}

impl<TState, THistory, TMempool, TErrHandler, TRuleSet, TProtocol>
    NodeView<TState, THistory, TMempool, TErrHandler, TRuleSet, TProtocol>
where
    TState: Cells + LedgerStateWrite + ConsensusIndexes + StakeDistribution + ValidatorCredentials,
    THistory: LedgerHistoryWrite + LedgerHistoryReadSync,
    TErrHandler: ErrorHandler,
    TRuleSet: ConsensusRuleSet,
    TProtocol: ProtocolParams,
{
    fn on_event(&self, event: NodeViewIn) {
        match event {
            NodeViewIn::ApplyModifier(md) => {
                self.apply_modifier(md)
                    .unwrap_or_else(|e| self.err_handler.on_invalid_modifier(e));
            }
        }
    }

    fn apply_modifier(&self, modifier: Modifier) -> Result<(), InvalidModifier> {
        match modifier {
            Modifier::BlockHeader(hd) => {
                validate_block_header(hd, &self.history, &self.state, &self.rules, &self.protocol)
                    .result()
                    .map(|valid_hd| self.history.apply_header(valid_hd))
            }
            Modifier::BlockBody(blk) => {
                todo!()
            }
            Modifier::Transaction(_) => {
                todo!()
            }
        }
    }
}

impl<TState, THistory, TMempool, TErrHandler, TRuleSet, TProtocol> Stream
    for NodeView<TState, THistory, TMempool, TErrHandler, TRuleSet, TProtocol>
where
    TState: Cells + LedgerStateWrite + ConsensusIndexes + StakeDistribution + ValidatorCredentials + Unpin,
    THistory: LedgerHistoryWrite + LedgerHistoryReadSync + Unpin,
    TMempool: Unpin,
    TErrHandler: ErrorHandler + Unpin,
    TRuleSet: ConsensusRuleSet + Unpin,
    TProtocol: ProtocolParams + Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            match self.inbox.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => {
                    self.on_event(event);
                    continue;
                }
                Poll::Pending => {}
                Poll::Ready(None) => unreachable!(),
            }
            return Poll::Pending;
        }
    }
}

#[derive(Clone)]
pub struct NodeViewMailbox {
    inner: Sender<NodeViewIn>,
}

impl NodeViewMailbox {
    pub fn new(inner: Sender<NodeViewIn>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl NodeViewWriteAsync for NodeViewMailbox {
    async fn apply_modifier(&mut self, modifier: Modifier) {
        self.inner
            .send(NodeViewIn::ApplyModifier(modifier))
            .await
            .unwrap();
    }
}
