#[derive(Clone, Debug)]
pub enum TxEvent<T> {
    AppliedTx(T),
    UnappliedTx(T),
}

pub trait DataBridge {
    type TxType;
    fn get_components(self) -> DataBridgeComponents<Self::TxType>;
}

pub struct DataBridgeComponents<T> {
    /// Each consumer of the data bridge is given a receiver to stream transaction data.
    pub receiver: tokio::sync::mpsc::Receiver<TxEvent<T>>,
    /// Call `send(())` on this `Sender` to indicate that the bridge should start transmitting
    /// transaction data. Note that the receivers should have already been distributed to
    /// consumers.
    pub start_signal: tokio::sync::oneshot::Sender<()>,
}
