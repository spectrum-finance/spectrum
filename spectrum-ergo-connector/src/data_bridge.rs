use std::sync::Once;

use ergo_chain_sync::{
    cache::rocksdb::ChainCacheRocksDB,
    chain_sync_stream,
    client::{node::ErgoNodeHttpClient, types::Url},
    rocksdb::RocksConfig,
    ChainSync,
};
use ergo_lib::chain::transaction::Transaction;
use futures::StreamExt;
use isahc::{prelude::Configurable, HttpClient};
use spectrum_chain_connector::{DataBridge, DataBridgeComponents, TxEvent};
use spectrum_offchain::event_source::{data::LedgerTxEvent, event_source_ledger};

pub struct ErgoDataBridge {
    pub receiver: tokio::sync::mpsc::Receiver<TxEvent<(ergo_lib::chain::transaction::Transaction, u32)>>,
    tx_start: tokio::sync::oneshot::Sender<()>,
}

pub struct ErgoDataBridgeConfig {
    pub http_client_timeout_duration_secs: u32,
    pub chain_sync_starting_height: u32,
    pub chain_cache_db_path: String,
    pub node_addr: Url,
}

impl ErgoDataBridge {
    pub fn new(config: ErgoDataBridgeConfig) -> Self {
        let (tx, receiver) = tokio::sync::mpsc::channel(16);
        let (tx_start, rx_start) = tokio::sync::oneshot::channel();

        tokio::spawn(run_bridge(tx, rx_start, config));

        ErgoDataBridge { receiver, tx_start }
    }
}

impl DataBridge for ErgoDataBridge {
    type TxType = (ergo_lib::chain::transaction::Transaction, u32);

    fn get_components(self) -> DataBridgeComponents<Self::TxType> {
        DataBridgeComponents {
            receiver: self.receiver,
            start_signal: self.tx_start,
        }
    }
}

async fn run_bridge(
    tx: tokio::sync::mpsc::Sender<TxEvent<(ergo_lib::chain::transaction::Transaction, u32)>>,
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
        .timeout(std::time::Duration::from_secs(
            http_client_timeout_duration_secs as u64,
        ))
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
            LedgerTxEvent::AppliedTx { tx, height, .. } => TxEvent::AppliedTx((tx, height)),
            LedgerTxEvent::UnappliedTx(tx) => {
                let height = greatest_height(&tx);
                TxEvent::UnappliedTx((tx, height))
            }
        };
        tx.send(event).await.unwrap();
    }
}

/// Returns greatest reported height of all output boxes of the TX
fn greatest_height(tx: &Transaction) -> u32 {
    tx.outputs.iter().fold(0, |acc, x| {
        if x.creation_height > acc {
            x.creation_height
        } else {
            acc
        }
    })
}

#[cfg(test)]
mod tests {
    use ergo_chain_sync::client::types::Url;
    use spectrum_chain_connector::{DataBridge, DataBridgeComponents, TxEvent};

    use super::{ErgoDataBridge, ErgoDataBridgeConfig};

    #[tokio::test]
    async fn test_data_bridge() {
        let config = ErgoDataBridgeConfig {
            http_client_timeout_duration_secs: 50,
            chain_sync_starting_height: 970000,
            chain_cache_db_path: String::from("tmp/"),
            node_addr: Url::try_from(String::from("http://213.239.193.208:9053")).unwrap(),
        };
        let ergo_bridge = ErgoDataBridge::new(config);
        let DataBridgeComponents {
            mut receiver,
            start_signal,
        } = ergo_bridge.get_components();

        start_signal.send(()).unwrap();
        for _ in 0..10 {
            let tx = receiver.recv().await.unwrap();
            match tx {
                TxEvent::AppliedTx((tx, _)) => {
                    let height = tx.outputs.first().creation_height;
                    println!("AppliedTx: {:?}, height: {}", tx.id(), height);
                }
                TxEvent::UnappliedTx((tx, _)) => {
                    let height = tx.outputs.first().creation_height;
                    println!("UnappliedTx: {:?}, height: {}", tx.id(), height);
                }
            }
        }
    }
}
