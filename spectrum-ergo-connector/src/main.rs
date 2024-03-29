use async_stream::stream;
use chrono::Duration;
use clap::{arg, command, Parser};
use data_bridge::{ErgoDataBridge, ErgoDataBridgeConfig};
use ergo_chain_sync::client::{node::ErgoNodeHttpClient, types::Url};
use ergo_connector::ErgoConnector;
use ergo_lib::{
    chain::transaction::{Transaction, TxIoVec},
    ergo_chain_types::EcPoint,
    ergotree_ir::{
        chain::{
            address::{AddressEncoder, NetworkPrefix},
            ergo_box::BoxId,
            token::TokenId,
        },
        ergo_tree::ErgoTree,
    },
};
use futures::StreamExt;
use isahc::{config::Configurable, HttpClient};
use log::info;
use rocksdb::{vault_boxes::VaultUtxoRepoRocksDB, withdrawals::WithdrawalRepoRocksDB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::serde_as;
use spectrum_chain_connector::{
    ChainTxEvent, ConnectorMsgOut, ConnectorRequest, ConnectorResponse, DataBridge, DataBridgeComponents,
    TxEvent,
};
use spectrum_deploy_lm_pool::Explorer;
use spectrum_ergo_connector::AncillaryVaultInfo;
use spectrum_ledger::cell::SValue;
use spectrum_offchain::network::ErgoNetwork as EN;
use tokio_stream::wrappers::ReceiverStream;
use tokio_unix_ipc::{symmetric_channel, Bootstrapper};

use crate::{
    rocksdb::{
        deposit::DepositRepoRocksDB, ergo_tx_event_history::ErgoTxEventHistoryRocksDB,
        tx_retry_scheduler::TxRetrySchedulerRocksDB, vault_boxes::ErgoNotarizationBounds,
    },
    script::ExtraErgoData,
};

mod committee;
mod data_bridge;
mod deposit;
mod ergo_connector;
mod rocksdb;
mod script;
mod tx_event;
mod tx_in_progress;
mod vault_utxo;

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();
    let raw_config = std::fs::read_to_string(args.config_path).expect("Cannot load configuration file");
    let config_proto: AppConfigProto = serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
    let config = AppConfig::from(config_proto);

    if let Some(log4rs_path) = args.log4rs_path {
        log4rs::init_file(log4rs_path, Default::default()).unwrap();
    } else {
        log4rs::init_file(config.log4rs_yaml_path, Default::default()).unwrap();
    }

    let node_url = config.node_addr.clone();

    let ergo_bridge_config = ErgoDataBridgeConfig {
        http_client_timeout_duration_secs: config.http_client_timeout_duration_secs,
        chain_sync_starting_height: config.chain_sync_starting_height,
        chain_cache_db_path: config.chain_cache_db_path,
        node_addr: config.node_addr,
    };

    let ergo_bridge = ErgoDataBridge::new(ergo_bridge_config);
    let DataBridgeComponents {
        receiver: data_bridge_receiver,
        start_signal,
    } = ergo_bridge.get_components();

    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(
            config.http_client_timeout_duration_secs as u64,
        ))
        .build()
        .unwrap();
    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };

    let node = ErgoNodeHttpClient::new(client, node_url);

    let mut data_inputs = vec![];
    for box_id in config.committee_box_ids {
        let ergo_box = explorer.get_box(box_id).await.unwrap();
        data_inputs.push(ergo_box);
    }

    let withdrawal_repo = WithdrawalRepoRocksDB::new(&config.withdrawals_store_db_path);
    let vault_box_repo = VaultUtxoRepoRocksDB::new(&config.vault_boxes_store_db_path);
    let deposit_repo = DepositRepoRocksDB::new(&config.deposits_store_db_path);

    let unix_socket_path = config.unix_socket_path.clone();

    let (connector_response_tx, connector_response_rx) = tokio::sync::mpsc::channel::<
        ConnectorResponse<ExtraErgoData, ErgoNotarizationBounds, BoxId, AncillaryVaultInfo>,
    >(10);

    let (request_to_connector_tx, mut request_to_connector_rx) =
        tokio::sync::mpsc::channel::<ConnectorRequest<ExtraErgoData, BoxId>>(10);

    // This is the blue coloured task pictured in the Connector documentation.
    tokio::spawn(manage_unix_socket_communications_task(
        connector_response_rx,
        request_to_connector_tx,
        unix_socket_path,
    ));

    let mut ergo_connector = ErgoConnector::new(
        vault_box_repo,
        withdrawal_repo,
        deposit_repo,
        config.committee_guarding_script,
        config.committee_public_keys,
        config.vault_utxo_token_id,
        TxIoVec::try_from(data_inputs).unwrap(),
        config.chain_sync_starting_height,
        ErgoTxEventHistoryRocksDB::new(&config.moved_value_history_db_path),
        TxRetrySchedulerRocksDB::new(
            &config.tx_retry_db_path,
            config.tx_retry_config.retry_delay_duration.num_seconds(),
            config.tx_retry_config.max_retries,
        )
        .await,
    )
    .unwrap();

    enum StreamValueFrom {
        Chain(TxEvent<(Transaction, u32)>),
        Driver(Option<ConnectorRequest<ExtraErgoData, BoxId>>),
        ResubmitTx,
    }

    type CombinedStream = std::pin::Pin<Box<dyn futures::stream::Stream<Item = StreamValueFrom> + Send>>;

    // Convert the tokio_unix_ipc Receiver into a stream.
    let consensus_driver_stream = stream! {
        loop {
            yield request_to_connector_rx.recv().await;
        }
    };

    // Every minute we check whether a SN TX needs a resubmission.
    let resubmit_tx_stream = stream! {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            yield ();
        }
    };

    let streams: Vec<CombinedStream> = vec![
        ReceiverStream::new(data_bridge_receiver)
            .map(StreamValueFrom::Chain)
            .boxed(),
        consensus_driver_stream.map(StreamValueFrom::Driver).boxed(),
        resubmit_tx_stream.map(|_| StreamValueFrom::ResubmitTx).boxed(),
    ];
    let mut combined_stream = futures::stream::select_all(streams);

    let _ = start_signal.send(());

    while let Some(m) = combined_stream.next().await {
        match m {
            StreamValueFrom::Chain(tx_event) => {
                ergo_connector.handle(tx_event).await;
            }
            StreamValueFrom::Driver(msg_in) => {
                if let Some(request) = msg_in {
                    match request {
                        ConnectorRequest::ValidateAndProcessWithdrawals(report) => {
                            let current_height = node.get_height().await;
                            let vault_utxo = explorer
                                .get_box(*report.additional_chain_data.vault_utxos.first().unwrap())
                                .await
                                .unwrap();
                            ergo_connector
                                .withdraw_value(*report.clone(), false, vault_utxo, &node)
                                .await;

                            let status = ergo_connector.get_connector_status(current_height).await;

                            let messages = vec![];
                            connector_response_tx
                                .send(ConnectorResponse { status, messages })
                                .await
                                .unwrap();
                        }

                        ConnectorRequest::ProcessDeposits => {
                            let current_height = node.get_height().await;
                            ergo_connector.process_deposits(false, &node).await;
                            let status = ergo_connector.get_connector_status(current_height).await;

                            let messages = vec![];
                            connector_response_tx
                                .send(ConnectorResponse { status, messages })
                                .await
                                .unwrap();
                        }

                        ConnectorRequest::RequestTxsToNotarize(constraints) => {
                            let res = ergo_connector.select_txs_to_notarize(constraints).await;

                            if let Ok(bounds) = res {
                                let current_height = node.get_height().await;
                                let status = ergo_connector.get_connector_status(current_height).await;
                                let messages = vec![ConnectorMsgOut::ProposedTxsToNotarize(bounds)];
                                info!(target: "vault", "Responding to RequestTxsToNotarize. status: {:?}, messages: {:?}", status, messages);

                                connector_response_tx
                                    .send(ConnectorResponse { status, messages })
                                    .await
                                    .unwrap();
                            }
                        }

                        ConnectorRequest::SyncFrom(point) => {
                            let mut messages: Vec<_> = ergo_connector
                                .sync_consensus_driver(point.as_ref().map(|p| u64::from(p.point) as u32))
                                .await
                                .into_iter()
                                .map(|ergo_mv| ConnectorMsgOut::TxEvent(ChainTxEvent::from(ergo_mv)))
                                .collect();
                            if let Some(genesis_vault_utxo) = ergo_connector.get_genesis_vault_utxo() {
                                if point.is_none() {
                                    info!(target: "vault", "PUSHING OUT GENESIS VAULT UTXO");
                                    messages.push(ConnectorMsgOut::GenesisVaultUtxo(SValue::from(
                                        &genesis_vault_utxo,
                                    )));
                                }
                            }
                            let current_height = node.get_height().await;
                            let status = ergo_connector.get_connector_status(current_height).await;
                            info!(
                                target: "vault",
                                "respond to SyncFrom({:?}). Current height: {} status: {:?}, messages: {:?}",
                                point, current_height, status, messages
                            );
                            connector_response_tx
                                .send(ConnectorResponse { status, messages })
                                .await
                                .unwrap();
                        }

                        ConnectorRequest::AcknowledgeConfirmedTx(identifier, point) => {
                            ergo_connector.acknowledge_confirmed_tx(&identifier).await;
                            let messages: Vec<_> = ergo_connector
                                .sync_consensus_driver(Some(u64::from(point.point) as u32))
                                .await
                                .into_iter()
                                .map(|ergo_mv| ConnectorMsgOut::TxEvent(ChainTxEvent::from(ergo_mv)))
                                .collect();
                            let current_height = node.get_height().await;
                            let status = ergo_connector.get_connector_status(current_height).await;
                            info!(target: "vault", "respond to AcknowledgeConfirmedTx. status: {:?}, messages: {:?}", status, messages);
                            connector_response_tx
                                .send(ConnectorResponse { status, messages })
                                .await
                                .unwrap();
                        }

                        ConnectorRequest::AcknowledgeAbortedTx(identifier, point) => {
                            ergo_connector.acknowledge_aborted_tx(&identifier).await;
                            let messages: Vec<_> = ergo_connector
                                .sync_consensus_driver(Some(u64::from(point.point) as u32))
                                .await
                                .into_iter()
                                .map(|ergo_mv| ConnectorMsgOut::TxEvent(ChainTxEvent::from(ergo_mv)))
                                .collect();
                            let current_height = node.get_height().await;
                            let status = ergo_connector.get_connector_status(current_height).await;
                            info!(target: "vault", "respond to AcknowledgeAbortedTx. status: {:?}, messages: {:?}", status, messages);
                            connector_response_tx
                                .send(ConnectorResponse { status, messages })
                                .await
                                .unwrap();
                        }

                        ConnectorRequest::Disconnect => {
                            unreachable!("");
                        }

                        ConnectorRequest::RotateCommittee => todo!(),
                    }
                }
            }

            StreamValueFrom::ResubmitTx => {
                ergo_connector.handle_tx_resubmission(&node).await;
            }
        }
    }
}

async fn manage_unix_socket_communications_task<S, T, U, V>(
    connector_response_rx: tokio::sync::mpsc::Receiver<ConnectorResponse<S, T, U, V>>,
    request_to_connector_tx: tokio::sync::mpsc::Sender<ConnectorRequest<S, U>>,
    unix_socket_path: String,
) where
    S: std::fmt::Debug + Send + Serialize + DeserializeOwned + 'static,
    T: Send + Serialize + DeserializeOwned + 'static,
    U: std::fmt::Debug + Send + Serialize + DeserializeOwned + 'static,
    V: Send + Serialize + DeserializeOwned + 'static,
{
    let (driver_req_tx, mut driver_req_rx) = tokio::sync::mpsc::channel::<ConnectorRequest<S, U>>(10);

    // The request-forwarder task. It forwards requests from the driver to the Connector.
    tokio::spawn(async move {
        while let Some(req) = driver_req_rx.recv().await {
            // Pass on this request to the Connector
            request_to_connector_tx.send(req).await.unwrap();
        }
    });

    let (response_sender_tx, response_sender_rx) =
        tokio::sync::mpsc::channel::<tokio_unix_ipc::Sender<ConnectorResponse<S, T, U, V>>>(10);

    // Merged stream
    enum MergedStream<S, T, U, V> {
        NewUnixSender(tokio_unix_ipc::Sender<ConnectorResponse<S, T, U, V>>),
        VaultManagerResponse(Box<ConnectorResponse<S, T, U, V>>),
    }

    type CombinedStream<S, T, U, V> =
        std::pin::Pin<Box<dyn futures::stream::Stream<Item = MergedStream<S, T, U, V>> + Send>>;

    let streams: Vec<CombinedStream<S, T, U, V>> = vec![
        ReceiverStream::new(response_sender_rx)
            .map(MergedStream::NewUnixSender)
            .boxed(),
        ReceiverStream::new(connector_response_rx)
            .map(|r| MergedStream::VaultManagerResponse(Box::new(r)))
            .boxed(),
    ];
    let mut combined_stream = futures::stream::select_all(streams);

    // The response-forwarder task. It forwards responses from the Connector to a connected driver.
    tokio::spawn(async move {
        let mut current_tx = None;
        while let Some(m) = combined_stream.next().await {
            match m {
                MergedStream::NewUnixSender(new_tx) => current_tx = Some(new_tx),
                MergedStream::VaultManagerResponse(response) => {
                    if let Some(ref tx) = current_tx {
                        tx.send(*response).await.unwrap();
                    }
                }
            }
        }
    });

    loop {
        let (req_tx, req_rx) = symmetric_channel::<ConnectorRequest<S, U>>().unwrap();
        let (resp_tx, resp_rx) = symmetric_channel::<ConnectorResponse<S, T, U, V>>().unwrap();
        let bootstrapper = Bootstrapper::bind(unix_socket_path.clone()).unwrap();
        bootstrapper.send((req_tx, resp_rx)).await.unwrap();

        response_sender_tx.send(resp_tx).await.unwrap();
        let driver_req_tx = driver_req_tx.clone();

        while let Ok(req) = req_rx.recv().await {
            match req {
                ConnectorRequest::Disconnect => {
                    break;
                }
                e => {
                    // Pass off to task above, which forwards to the Connector
                    let _ = driver_req_tx.send(e).await;
                }
            }
        }
    }
}

struct AppConfig {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    tx_retry_config: TxRetryConfig,
    log4rs_yaml_path: String,
    tx_retry_db_path: String,
    withdrawals_store_db_path: String,
    deposits_store_db_path: String,
    vault_boxes_store_db_path: String,
    moved_value_history_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<EcPoint>,
    committee_box_ids: Vec<BoxId>,
    /// Base58 encoding of guarding script of committee boxes
    committee_guarding_script: ErgoTree,
    vault_utxo_token_id: TokenId,
}

#[derive(Deserialize)]
struct AppConfigProto {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    tx_retry_config: TxRetryConfig,
    log4rs_yaml_path: String,
    tx_retry_db_path: String,
    withdrawals_store_db_path: String,
    vault_boxes_store_db_path: String,
    deposits_store_db_path: String,
    moved_value_history_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<String>,
    committee_box_ids: Vec<BoxId>,
    /// Base58 encoding of guarding script of committee boxes
    committee_guarding_script: String,
    vault_utxo_token_id: TokenId,
}

impl From<AppConfigProto> for AppConfig {
    fn from(value: AppConfigProto) -> Self {
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str(&value.committee_guarding_script)
            .unwrap();
        let committee_guarding_script = address.script().unwrap();

        let committee_public_keys = value
            .committee_public_keys
            .into_iter()
            .map(|pk_str| {
                let bytes = base16::decode(&pk_str).unwrap();
                let pk = k256::PublicKey::from_sec1_bytes(&bytes).unwrap();
                EcPoint::from(pk.to_projective())
            })
            .collect();
        Self {
            node_addr: value.node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            chain_sync_starting_height: value.chain_sync_starting_height,
            tx_retry_config: value.tx_retry_config,
            log4rs_yaml_path: value.log4rs_yaml_path,
            tx_retry_db_path: value.tx_retry_db_path,
            withdrawals_store_db_path: value.withdrawals_store_db_path,
            deposits_store_db_path: value.deposits_store_db_path,
            vault_boxes_store_db_path: value.vault_boxes_store_db_path,
            moved_value_history_db_path: value.moved_value_history_db_path,
            chain_cache_db_path: value.chain_cache_db_path,
            unix_socket_path: value.unix_socket_path,
            committee_public_keys,
            committee_box_ids: value.committee_box_ids,
            committee_guarding_script,
            vault_utxo_token_id: value.vault_utxo_token_id,
        }
    }
}

#[serde_with::serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxRetryConfig {
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub retry_delay_duration: Duration,
    pub max_retries: u32,
}

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Spectrum Finance Ergo Connector", long_about = None)]
struct AppArgs {
    /// Path to the YAML configuration file.
    #[arg(long, short)]
    config_path: String,
    /// Optional path to the log4rs YAML configuration file. NOTE: overrides path specified in config YAML file.
    #[arg(long, short)]
    log4rs_path: Option<String>,
}
