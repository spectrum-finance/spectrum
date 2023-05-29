use async_trait::async_trait;
use futures::channel::mpsc::Sender;
use futures::SinkExt;

use crate::Modifier;

pub mod history;
pub mod state;

#[async_trait::async_trait]
pub trait LedgerViewWriteAsync: Send + Sync + Clone {
    async fn apply_modifier(&mut self, modifier: Modifier);
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LedgerViewIn {
    ApplyModifier(Modifier),
}

#[derive(Clone)]
pub struct LedgerViewMailbox {
    inner: Sender<LedgerViewIn>,
}

impl LedgerViewMailbox {
    pub fn new(inner: Sender<LedgerViewIn>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl LedgerViewWriteAsync for LedgerViewMailbox {
    async fn apply_modifier(&mut self, modifier: Modifier) {
        self.inner
            .send(LedgerViewIn::ApplyModifier(modifier))
            .await
            .unwrap();
    }
}
