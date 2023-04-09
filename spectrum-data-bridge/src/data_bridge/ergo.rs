use std::sync::Once;

use ergo_chain_sync::{
    cache::rocksdb::ChainCacheRocksDB,
    chain_sync_stream,
    client::{node::ErgoNodeHttpClient, types::Url},
    rocksdb::RocksConfig,
    ChainSync,
};
use futures::StreamExt;
use isahc::{prelude::Configurable, HttpClient};
use spectrum_offchain::event_source::{data::LedgerTxEvent, event_source_ledger};

use crate::{DataBridge, DataBridgeComponents, TxEvent};

pub struct ErgoDataBridge {
    pub receivers: Vec<tokio::sync::broadcast::Receiver<TxEvent<ergo_lib::chain::transaction::Transaction>>>,
    tx_start: tokio::sync::oneshot::Sender<()>,
}

pub struct ErgoDataBridgeConfig {
    pub http_client_timeout_duration_secs: u64,
    pub chain_sync_starting_height: u32,
    pub chain_cache_db_path: String,
    pub node_addr: Url,
}

impl ErgoDataBridge {
    pub fn new(num_receivers: usize, config: ErgoDataBridgeConfig) -> Self {
        let (tx, rx1) = tokio::sync::broadcast::channel(16);
        let mut receivers = Vec::with_capacity(num_receivers);
        receivers.push(rx1);

        for _ in 0..(num_receivers - 1) {
            receivers.push(tx.subscribe());
        }
        let (tx_start, rx_start) = tokio::sync::oneshot::channel();

        tokio::spawn(run_bridge(tx, rx_start, config));

        ErgoDataBridge { receivers, tx_start }
    }
}

impl DataBridge for ErgoDataBridge {
    type TxType = ergo_lib::chain::transaction::Transaction;

    fn get_components(self) -> DataBridgeComponents<Self::TxType> {
        DataBridgeComponents {
            receivers: self.receivers,
            start_signal: self.tx_start,
        }
    }
}

async fn run_bridge(
    tx: tokio::sync::broadcast::Sender<TxEvent<ergo_lib::chain::transaction::Transaction>>,
    rx_start: tokio::sync::oneshot::Receiver<()>,
    config: ErgoDataBridgeConfig,
) {
    // Wait for signal to start
    rx_start.await.unwrap();

    let ErgoDataBridgeConfig {
        http_client_timeout_duration_secs,
        chain_sync_starting_height,
        chain_cache_db_path,
        node_addr,
    } = config;
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(http_client_timeout_duration_secs))
        .build()
        .unwrap();
    let node = ErgoNodeHttpClient::new(client, node_addr);
    let cache = ChainCacheRocksDB::new(RocksConfig {
        db_path: chain_cache_db_path,
    });
    let signal_tip_reached = Once::new();
    let chain_sync = ChainSync::init(
        chain_sync_starting_height,
        &node,
        cache,
        Some(&signal_tip_reached),
    )
    .await;

    let mut tx_stream = Box::pin(event_source_ledger(chain_sync_stream(chain_sync)));
    while let Some(event) = tx_stream.next().await {
        let event = match event {
            LedgerTxEvent::AppliedTx { tx, .. } => TxEvent::AppliedTx(tx),
            LedgerTxEvent::UnappliedTx(tx) => TxEvent::UnappliedTx(tx),
        };
        tx.send(event).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use ergo_chain_sync::client::types::Url;

    use crate::{
        data_bridge::ergo::{ErgoDataBridge, ErgoDataBridgeConfig},
        DataBridge, DataBridgeComponents, TxEvent,
    };

    #[tokio::test]
    async fn test_data_bridge() {
        let config = ErgoDataBridgeConfig {
            http_client_timeout_duration_secs: 50,
            chain_sync_starting_height: 970000,
            chain_cache_db_path: String::from("tmp/"),
            node_addr: Url::try_from(String::from("http://213.239.193.208:9053")).unwrap(),
        };
        let ergo_bridge = ErgoDataBridge::new(1, config);
        let DataBridgeComponents {
            mut receivers,
            start_signal,
        } = ergo_bridge.get_components();

        start_signal.send(()).unwrap();
        let mut rx = receivers.pop().unwrap();
        for _ in 0..10 {
            let tx = rx.recv().await.unwrap();
            match tx {
                TxEvent::AppliedTx(tx) => {
                    let height = tx.outputs[0].creation_height;
                    println!("AppliedTx: {:?}, height: {}", tx.id(), height);
                }
                TxEvent::UnappliedTx(tx) => {
                    let height = tx.outputs[0].creation_height;
                    println!("UnappliedTx: {:?}, height: {}", tx.id(), height);
                }
            }
        }
    }
}
