use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{Receiver, Sender};
use futures::{SinkExt, Stream, StreamExt};

use spectrum_ledger::Modifier;

use crate::history::{InvalidBlockSection, LedgerHistory};
use crate::state::{CellPool, LedgerStateWrite};

#[derive(Clone, Debug)]
pub enum NodeViewIn {
    ApplyModifier(Modifier),
}

pub trait ErrorHandler {
    fn on_invalid_modifier(&self, err: InvalidModifier);
}

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum InvalidModifier {
    #[error("Modifier is invalid")]
    InvalidSection(InvalidBlockSection),
}

pub struct NodeView<TState, THistory, TMempool, TErrh> {
    state: TState,
    history: THistory,
    mempool: TMempool,
    err_handler: TErrh,
    inbox: Receiver<NodeViewIn>,
}

impl<TState, THistory, TMempool, TErrh> NodeView<TState, THistory, TMempool, TErrh>
where
    TState: CellPool + LedgerStateWrite,
    THistory: LedgerHistory,
    TErrh: ErrorHandler,
{
    fn on_event(&self, event: NodeViewIn) {
        match event {
            NodeViewIn::ApplyModifier(md) => {
                self.apply_modifier(&md)
                    .unwrap_or_else(|e| self.err_handler.on_invalid_modifier(e));
            }
        }
    }

    fn apply_modifier(&self, modifier: &Modifier) -> Result<(), InvalidModifier> {
        match modifier {
            Modifier::BlockHeader(hd) => self
                .history
                .apply_header(hd)
                .map_err(|err| InvalidModifier::InvalidSection(InvalidBlockSection::InvalidHeader(err))),
            Modifier::BlockBody(blk) => self
                .history
                .apply_body(blk)
                .map_err(|err| InvalidModifier::InvalidSection(InvalidBlockSection::InvalidBody(err)))
                .and_then(|_| {
                    self.state.apply_block(&blk).map_err(|err| {
                        InvalidModifier::InvalidSection(InvalidBlockSection::InvalidBlock(err))
                    })
                }),
            Modifier::Transaction(_) => {
                todo!()
            }
        }
    }
}

impl<TState, THistory, TMempool, TErrh> Stream for NodeView<TState, THistory, TMempool, TErrh>
where
    TState: CellPool + LedgerStateWrite + Unpin,
    THistory: LedgerHistory + Unpin,
    TMempool: Unpin,
    TErrh: ErrorHandler + Unpin,
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

#[async_trait::async_trait]
pub trait NodeViewWriteAsync: Send + Sync + Clone {
    async fn apply_modifier(&mut self, modifier: Modifier);
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
