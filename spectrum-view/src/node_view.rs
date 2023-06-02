use std::pin::Pin;
use std::task::{Context, Poll};

use futures::channel::mpsc::{Receiver, Sender};
use futures::{SinkExt, Stream};

use spectrum_ledger::block::BlockSection;
use spectrum_ledger::Modifier;

use crate::history::{InvalidBlockSection, LedgerHistory};
use crate::state::LedgerState;

#[derive(Clone, Debug)]
pub enum NodeViewIn {
    ApplyModifier(Modifier),
}

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum InvalidModifier {
    #[error("Modifier is invalid")]
    InvalidSection(InvalidBlockSection),
}

pub struct NodeView<TState, THistory, TMempool> {
    state: TState,
    history: THistory,
    mempool: TMempool,
    inbox: Receiver<NodeViewIn>,
}

impl<TState, THistory, TMempool> NodeView<TState, THistory, TMempool>
where
    TState: LedgerState,
    THistory: LedgerHistory,
{
    fn on_event(&self, event: NodeViewIn) {
        match event {
            NodeViewIn::ApplyModifier(md) => {
                self.apply_modifier(md);
            }
        }
    }

    fn apply_modifier(&self, modifier: Modifier) -> Result<(), InvalidModifier> {
        match modifier {
            Modifier::BlockHeader(hd) => self
                .history
                .apply_section(BlockSection::from(hd))
                .map_err(|err| InvalidModifier::InvalidSection(err)),
        }
    }
}

impl<TState, THistory, TMempool> Stream for NodeView<TState, THistory, TMempool>
where
    TState: LedgerState + Unpin,
    THistory: LedgerHistory + Unpin,
    TMempool: Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.inbox), cx) {
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
