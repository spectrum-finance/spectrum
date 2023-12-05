use std::{
    collections::HashMap,
    os::unix::net::{UnixListener, UnixStream},
    sync::Arc,
};

use async_stream::stream;
use bounded_integer::BoundedU8;
use chrono::Duration;
use clap::{arg, command, Parser};
use data_bridge::ergo::{ErgoDataBridge, ErgoDataBridgeConfig};
use ergo_chain_sync::client::{
    node::{ErgoNetwork, ErgoNodeHttpClient},
    types::Url,
};
use ergo_lib::{
    chain::transaction::{Transaction, TxIoVec},
    ergo_chain_types::EcPoint,
    ergotree_ir::{
        chain::{
            address::{AddressEncoder, NetworkPrefix},
            ergo_box::BoxId,
        },
        ergo_tree::ErgoTree,
    },
};
use futures::{stream::select_all, StreamExt};
use isahc::{config::Configurable, HttpClient};
use k256::PublicKey;
use log::info;
use rocksdb::{vault_boxes::VaultBoxRepoRocksDB, withdrawals::WithdrawalRepoRocksDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use spectrum_chain_connector::{
    DataBridge, DataBridgeComponents, MovedValue, TxEvent, VaultMsgOut, VaultRequest, VaultResponse,
    VaultStatus,
};
use spectrum_crypto::digest::blake2b256_hash;
use spectrum_deploy_lm_pool::Explorer;
use spectrum_handel::Threshold;
use spectrum_ledger::cell::ProgressPoint;
use spectrum_offchain::{
    event_sink::handlers::types::IntoBoxCandidate, network::ErgoNetwork as EN,
    transaction::TransactionCandidate,
};
use spectrum_offchain_lm::{
    data::miner::MinerOutput,
    ergo::{NanoErg, DEFAULT_MINER_FEE, MIN_SAFE_BOX_VALUE},
    prover::{SeedPhrase, SigmaProver},
};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_unix_ipc::{symmetric_channel, Bootstrapper, Receiver, Sender};
use vault::VaultHandler;

use crate::{
    rocksdb::moved_value_history::InMemoryMovedValueHistory,
    script::{ExtraErgoData, SignatureAggregationWithNotarizationElements},
};

mod committee;
mod data_bridge;
mod rocksdb;
mod script;
mod vault;

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();
    let raw_config = std::fs::read_to_string(args.config_path).expect("Cannot load configuration file");
    let config_proto: AppConfigProto = serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
    let mut config = AppConfig::from(config_proto);

    if let Some(log4rs_path) = args.log4rs_path {
        log4rs::init_file(log4rs_path, Default::default()).unwrap();
    } else {
        log4rs::init_file(config.log4rs_yaml_path, Default::default()).unwrap();
    }

    let node_url = config.node_addr.clone();
    let mut seed = SeedPhrase::from(String::from(""));
    std::mem::swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    config.operator_funding_secret = SeedPhrase::from(secret_str.clone());
    let wallet = ergo_lib::wallet::Wallet::from_mnemonic(&secret_str, "").expect("Invalid wallet seed");

    let ergo_bridge_config = ErgoDataBridgeConfig {
        http_client_timeout_duration_secs: config.http_client_timeout_duration_secs,
        chain_sync_starting_height: config.chain_sync_starting_height,
        chain_cache_db_path: config.chain_cache_db_path,
        node_addr: config.node_addr,
    };

    let ergo_bridge = ErgoDataBridge::new(ergo_bridge_config);
    let DataBridgeComponents {
        receiver,
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
    let vault_box_repo = VaultBoxRepoRocksDB::new(&config.vault_boxes_store_db_path);

    let mut vault_handler = VaultHandler::new(
        vault_box_repo,
        withdrawal_repo,
        config.committee_guarding_script,
        config.committee_public_keys,
        TxIoVec::try_from(data_inputs).unwrap(),
        config.chain_sync_starting_height,
        InMemoryMovedValueHistory::new(),
    )
    .unwrap();

    let bootstrapper = Bootstrapper::new().unwrap();
    let path = bootstrapper.path().to_owned();
    let (msg_in_send, msg_in_recv) = symmetric_channel::<VaultRequest<ExtraErgoData>>().unwrap();
    let (msg_out_send, msg_out_recv) = symmetric_channel::<VaultResponse>().unwrap();

    enum C {
        FromChain(TxEvent<(Transaction, bool, u32)>),
        FromDriver(VaultRequest<ExtraErgoData>),
    }

    type CombinedStream = std::pin::Pin<Box<dyn futures::stream::Stream<Item = C> + Send>>;

    // Convert the tokio_unix_ipc Receiver into a stream.
    let consensus_driver_stream = stream! {
        loop {
            if let Ok(msg) = msg_in_recv.recv().await {
                yield msg;
            }
        }
    };

    let streams: Vec<CombinedStream> = vec![
        ReceiverStream::new(receiver).map(C::FromChain).boxed(),
        consensus_driver_stream.map(C::FromDriver).boxed(),
    ];
    let mut combined_stream = futures::stream::select_all(streams);

    bootstrapper.send((msg_in_send, msg_out_recv)).await.unwrap();
    let _ = start_signal.send(());

    while let Some(m) = combined_stream.next().await {
        match m {
            C::FromChain(tx_event) => {
                vault_handler.handle(tx_event).await;
            }
            C::FromDriver(msg_in) => {
                match msg_in {
                    VaultRequest::ExportValue(report) => {
                        let current_height = node.get_height().await;
                        let ergo_state_context = node.get_ergo_state_context().await.unwrap();
                        let vault_utxo = explorer
                            .get_box(report.additional_chain_data.vault_utxo)
                            .await
                            .unwrap();
                        let inputs = SignatureAggregationWithNotarizationElements::from(*report);
                        vault_handler
                            .export_value(
                                inputs,
                                ergo_state_context,
                                current_height,
                                vault_utxo,
                                &node,
                                &wallet,
                            )
                            .await;
                    }
                    VaultRequest::RequestTxsToNotarize(constraints) => {
                        let res = vault_handler.select_txs_to_notarize(constraints).await;

                        match res {
                            Ok((included_vault_utxos, term_cell_ix)) => (),
                            Err(e) => (),
                        }
                    }
                    VaultRequest::SyncFrom(point) => {
                        // mock driver doesn't do anything with it

                        let messages: Vec<_> = vault_handler
                            .sync_consensus_driver(point.map(|p| u64::from(p.point) as u32))
                            .await
                            .into_iter()
                            .map(|ergo_mv| VaultMsgOut::MovedValue(MovedValue::from(ergo_mv)))
                            .collect();
                        let current_height = node.get_height().await;
                        let status = vault_handler.get_vault_status(current_height);
                        msg_out_send
                            .send(VaultResponse { status, messages })
                            .await
                            .unwrap();
                    }
                    VaultRequest::RotateCommittee => todo!(),
                    VaultRequest::GetStatus => {
                        let current_height = node.get_height().await;
                        let response = vault_handler.get_vault_status_response(current_height);
                        msg_out_send.send(response).await.unwrap()
                    }
                }
            }
        }
    }
}

struct AppConfig {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    backlog_config: BacklogConfig,
    log4rs_yaml_path: String,
    withdrawals_store_db_path: String,
    vault_boxes_store_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<EcPoint>,
    committee_box_ids: Vec<BoxId>,
    /// Base58 encoding of guarding script of committee boxes
    committee_guarding_script: ErgoTree,
    operator_funding_secret: SeedPhrase,
}

#[derive(Deserialize)]
struct AppConfigProto {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    backlog_config: BacklogConfig,
    log4rs_yaml_path: String,
    withdrawals_store_db_path: String,
    vault_boxes_store_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<String>,
    committee_box_ids: Vec<BoxId>,
    /// Base58 encoding of guarding script of committee boxes
    committee_guarding_script: String,
    operator_funding_secret: String,
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
        let operator_funding_secret = SeedPhrase::from(value.operator_funding_secret);
        Self {
            node_addr: value.node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            chain_sync_starting_height: value.chain_sync_starting_height,
            backlog_config: value.backlog_config,
            log4rs_yaml_path: value.log4rs_yaml_path,
            withdrawals_store_db_path: value.withdrawals_store_db_path,
            vault_boxes_store_db_path: value.vault_boxes_store_db_path,
            chain_cache_db_path: value.chain_cache_db_path,
            unix_socket_path: value.unix_socket_path,
            committee_public_keys,
            committee_box_ids: value.committee_box_ids,
            committee_guarding_script,
            operator_funding_secret,
        }
    }
}

#[serde_with::serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BacklogConfig {
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub order_lifespan: Duration,
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub order_exec_time: Duration,
    pub retry_suspended_prob: BoundedU8<0, 100>,
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
