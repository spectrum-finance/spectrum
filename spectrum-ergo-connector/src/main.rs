use std::{collections::HashMap, os::unix::net::UnixStream, sync::Arc};

use bounded_integer::BoundedU8;
use chrono::Duration;
use clap::{arg, command, Parser};
use data_bridge::ergo::{ErgoDataBridge, ErgoDataBridgeConfig};
use ergo_chain_sync::client::types::Url;
use ergo_lib::{
    chain::transaction::TxIoVec,
    ergo_chain_types::EcPoint,
    ergotree_ir::chain::{
        address::{AddressEncoder, NetworkPrefix},
        ergo_box::BoxId,
    },
};
use futures::{stream::select_all, StreamExt};
use isahc::{config::Configurable, HttpClient};
use rocksdb::{vault_boxes::VaultBoxRepoRocksDB, withdrawals::WithdrawalRepoRocksDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use spectrum_chain_connector::{DataBridge, DataBridgeComponents, TxEvent, VaultMsgIn, VaultMsgOut};
use spectrum_crypto::digest::blake2b256_hash;
use spectrum_deploy_lm_pool::Explorer;
use spectrum_handel::Threshold;
use spectrum_offchain::{
    event_sink::handlers::types::IntoBoxCandidate, network::ErgoNetwork as EN,
    transaction::TransactionCandidate,
};
use spectrum_offchain_lm::{
    data::miner::MinerOutput,
    ergo::{NanoErg, DEFAULT_MINER_FEE, MIN_SAFE_BOX_VALUE},
    prover::{SeedPhrase, SigmaProver, Wallet},
};
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tokio_unix_ipc::channel_from_std;
use vault::VaultHandler;

mod committee;
mod data_bridge;
mod rocksdb;
mod script;
mod vault;

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();
    let raw_config = std::fs::read_to_string(args.config_path).expect("Cannot load configuration file");
    let config: AppConfig = serde_yaml::from_str(&raw_config).expect("Invalid configuration file");

    //if let Some(log4rs_path) = args.log4rs_path {
    //    log4rs::init_file(log4rs_path, Default::default()).unwrap();
    //} else {
    //    log4rs::init_file(config.log4rs_yaml_path, Default::default()).unwrap();
    //}

    let ergo_bridge_config = ErgoDataBridgeConfig {
        http_client_timeout_duration_secs: config.http_client_timeout_duration_secs,
        chain_sync_starting_height: config.chain_sync_starting_height,
        chain_cache_db_path: String::from(config.chain_cache_db_path),
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

    let mut data_inputs = vec![];
    for box_id_str in config.committee_box_ids {
        let box_id = BoxId::try_from(String::from(box_id_str)).unwrap();
        let ergo_box = explorer.get_box(box_id).await.unwrap();
        data_inputs.push(ergo_box);
    }

    let mut committee_public_keys = vec![];
    for encoded_key in &config.committee_public_keys {
        let bytes = base16::decode(&encoded_key).unwrap();
        let pk = k256::PublicKey::from_sec1_bytes(&bytes).unwrap();
        committee_public_keys.push(EcPoint::from(pk.to_projective()));
    }

    let withdrawal_repo = WithdrawalRepoRocksDB::new(config.withdrawals_store_db_path);
    let vault_box_repo = VaultBoxRepoRocksDB::new(config.vault_boxes_store_db_path);

    let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
    let address = encoder
        .parse_address_from_str(config.committee_guarding_script)
        .unwrap();
    let committee_guarding_script = address.script().unwrap();
    let vault_handler = Arc::new(Mutex::new(
        VaultHandler::new(
            vault_box_repo,
            withdrawal_repo,
            committee_guarding_script,
            committee_public_keys,
            TxIoVec::try_from(data_inputs).unwrap(),
        )
        .unwrap(),
    ));

    let chain_stream = Box::pin(ReceiverStream::new(receiver).then(|ev| async {
        vault_handler.lock().await.handle(ev).await;
    }));

    // Setup unix stream
    //let sock = UnixStream::connect(config.unix_socket_path).unwrap();
    //let (send, recv) = channel_from_std::<VaultMsgOut, VaultMsgIn>(sock).unwrap();

    //tokio::spawn(async move {
    //    loop {
    //        match recv.recv().await {
    //            Ok(msg) => match msg {
    //                VaultMsgIn::ExportValue(report) => {
    //                    // Just hard code committee boxes for now.

    //                    //
    //                }
    //                VaultMsgIn::RequestTxsToNotarize(constraints) => todo!(),
    //                VaultMsgIn::SyncFrom(point) => {
    //                    // What does the driver need?
    //                    // Needs to know inbound deposits, confirmed withdrawals, and any rollbacks of these operations.
    //                }
    //                VaultMsgIn::RotateCommittee => todo!(),
    //            },
    //            Err(e) => {}
    //        }
    //    }
    //});

    let _ = start_signal.send(());

    let mut app = select_all(vec![chain_stream]);
    loop {
        app.select_next_some().await;
    }
}

#[derive(Deserialize)]
struct AppConfig<'a> {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    backlog_config: BacklogConfig,
    log4rs_yaml_path: &'a str,
    withdrawals_store_db_path: &'a str,
    vault_boxes_store_db_path: &'a str,
    chain_cache_db_path: &'a str,
    unix_socket_path: &'a str,
    committee_public_keys: Vec<&'a str>,
    committee_box_ids: Vec<&'a str>,
    /// Base58 encoding of guarding script of committee boxes
    committee_guarding_script: &'a str,
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
