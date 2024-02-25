use spectrum_ledger::Modifier;

#[async_trait::async_trait]
pub trait NodeViewWriteAsync: Send + Sync + Clone {
    async fn apply_modifier(&mut self, modifier: Modifier);
}
