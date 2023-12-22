use std::path::PathBuf;

use async_stream::stream;
use bounded_integer::BoundedU8;
use chrono::Duration;
use clap::{arg, command, Parser};
use data_bridge::ergo::{ErgoDataBridge, ErgoDataBridgeConfig};
use ergo_chain_sync::client::{node::ErgoNodeHttpClient, types::Url};
use ergo_lib::{
    chain::transaction::{Transaction, TxIoVec},
    ergo_chain_types::EcPoint,
    ergotree_ir::{
        chain::{
            address::{AddressEncoder, NetworkPrefix},
            ergo_box::{box_value::BoxValue, BoxId},
            token::TokenId,
        },
        ergo_tree::ErgoTree,
    },
};
use futures::StreamExt;
use isahc::{config::Configurable, HttpClient};
use k256::{Secp256k1, SecretKey};
use log::info;
use rocksdb::{vault_boxes::VaultBoxRepoRocksDB, withdrawals::WithdrawalRepoRocksDB};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use spectrum_chain_connector::{
    DataBridge, DataBridgeComponents, Kilobytes, MovedValue, NotarizedReport, NotarizedReportConstraints,
    PendingExportStatus, ProtoTermCell, TxEvent, VaultMsgOut, VaultRequest, VaultResponse, VaultStatus,
};
use spectrum_crypto::digest::blake2b256_hash;
use spectrum_deploy_lm_pool::Explorer;
use spectrum_handel::Threshold;
use spectrum_ledger::{
    cell::{ProgressPoint, TermCell},
    interop::{Point, ReportCertificate},
    ChainId,
};
use spectrum_offchain::network::ErgoNetwork as EN;
use spectrum_sigma::sigma_aggregation::AggregateCertificate;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tokio_unix_ipc::{symmetric_channel, Bootstrapper, Receiver, Sender};
use vault::VaultHandler;

use crate::{
    rocksdb::{
        moved_value_history::MovedValueHistoryRocksDB, tx_retry_scheduler::ExportTxRetrySchedulerRocksDB,
        vault_boxes::ErgoNotarizationBounds,
    },
    script::{simulate_signature_aggregation_notarized_proofs, ErgoCell, ErgoTermCell, ExtraErgoData},
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
        config.vault_utxo_token_id,
        TxIoVec::try_from(data_inputs).unwrap(),
        config.chain_sync_starting_height,
        MovedValueHistoryRocksDB::new(&config.moved_value_history_db_path),
        ExportTxRetrySchedulerRocksDB::new(
            &config.export_tx_retry_config.db_path,
            config.export_tx_retry_config.retry_delay_duration.num_seconds(),
            config.export_tx_retry_config.max_retries,
        )
        .await,
    )
    .unwrap();

    let bootstrapper = Bootstrapper::bind(config.unix_socket_path).unwrap();
    let path = bootstrapper.path().to_owned();
    let (msg_in_send, msg_in_recv) = symmetric_channel::<VaultRequest<ExtraErgoData>>().unwrap();
    let (msg_out_send, msg_out_recv) =
        symmetric_channel::<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>().unwrap();

    enum StreamValueFrom {
        Chain(TxEvent<(Transaction, u32)>),
        Driver(VaultRequest<ExtraErgoData>),
        ResubmitExportTx,
    }

    type CombinedStream = std::pin::Pin<Box<dyn futures::stream::Stream<Item = StreamValueFrom> + Send>>;

    // Convert the tokio_unix_ipc Receiver into a stream.
    let consensus_driver_stream = stream! {
        loop {
            if let Ok(msg) = msg_in_recv.recv().await {
                yield msg;
            }
        }
    };

    // Every minute we check whether the export TX needs a resubmission.
    let resubmit_export_tx_stream = stream! {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            yield ();
        }
    };

    let streams: Vec<CombinedStream> = vec![
        ReceiverStream::new(receiver).map(StreamValueFrom::Chain).boxed(),
        consensus_driver_stream.map(StreamValueFrom::Driver).boxed(),
        resubmit_export_tx_stream
            .map(|_| StreamValueFrom::ResubmitExportTx)
            .boxed(),
    ];
    let mut combined_stream = futures::stream::select_all(streams);

    let participant_secret_keys = config.committee_secret_keys.clone();

    // Mock consensus driver
    tokio::spawn(mock_consensus_driver(path, participant_secret_keys));

    bootstrapper.send((msg_in_send, msg_out_recv)).await.unwrap();
    let _ = start_signal.send(());

    while let Some(m) = combined_stream.next().await {
        match m {
            StreamValueFrom::Chain(tx_event) => {
                vault_handler.handle(tx_event).await;
            }
            StreamValueFrom::Driver(msg_in) => {
                match msg_in {
                    VaultRequest::ExportValue(report) => {
                        let current_height = node.get_height().await;
                        let vault_utxo = explorer
                            .get_box(*report.additional_chain_data.vault_utxos.first().unwrap())
                            .await
                            .unwrap();
                        vault_handler
                            .export_value(*report.clone(), false, vault_utxo, &node)
                            .await;

                        let status = vault_handler.get_vault_status(current_height).await;

                        let messages = vec![];
                        msg_out_send
                            .send(VaultResponse { status, messages })
                            .await
                            .unwrap();
                    }

                    VaultRequest::RequestTxsToNotarize(constraints) => {
                        let res = vault_handler.select_txs_to_notarize(constraints).await;

                        if let Ok(bounds) = res {
                            let current_height = node.get_height().await;
                            let status = vault_handler.get_vault_status(current_height).await;
                            let messages = vec![VaultMsgOut::ProposedTxsToNotarize(bounds)];
                            info!(target: "vault", "Responding to RequestTxsToNotarize. status: {:?}, messages: {:?}", status, messages);

                            msg_out_send
                                .send(VaultResponse { status, messages })
                                .await
                                .unwrap();
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
                        let status = vault_handler.get_vault_status(current_height).await;
                        info!(target: "vault", "respond to SyncFrom. status: {:?}, messages: {:?}", status, messages);
                        msg_out_send
                            .send(VaultResponse { status, messages })
                            .await
                            .unwrap();
                    }

                    VaultRequest::AcknowledgeConfirmedExportTx(report, point) => {
                        vault_handler.acknowledge_confirmed_export_tx(&report).await;
                        let messages: Vec<_> = vault_handler
                            .sync_consensus_driver(Some(u64::from(point.point) as u32))
                            .await
                            .into_iter()
                            .map(|ergo_mv| VaultMsgOut::MovedValue(MovedValue::from(ergo_mv)))
                            .collect();
                        let current_height = node.get_height().await;
                        let status = vault_handler.get_vault_status(current_height).await;
                        info!(target: "vault", "respond to AcknowledgeConfirmedExportTx. status: {:?}, messages: {:?}", status, messages);
                        msg_out_send
                            .send(VaultResponse { status, messages })
                            .await
                            .unwrap();
                    }

                    VaultRequest::AcknowledgeAbortedExportTx(report, point) => {
                        vault_handler.acknowledge_aborted_export_tx(&report).await;
                        let messages: Vec<_> = vault_handler
                            .sync_consensus_driver(Some(u64::from(point.point) as u32))
                            .await
                            .into_iter()
                            .map(|ergo_mv| VaultMsgOut::MovedValue(MovedValue::from(ergo_mv)))
                            .collect();
                        let current_height = node.get_height().await;
                        let status = vault_handler.get_vault_status(current_height).await;
                        info!(target: "vault", "respond to AcknowledgeAbortedExportTx. status: {:?}, messages: {:?}", status, messages);
                        msg_out_send
                            .send(VaultResponse { status, messages })
                            .await
                            .unwrap();
                    }

                    VaultRequest::RotateCommittee => todo!(),
                }
            }
            StreamValueFrom::ResubmitExportTx => {
                vault_handler.handle_tx_resubmission(&node).await;
            }
        }
    }
}

async fn mock_consensus_driver(path: PathBuf, participant_secret_keys: Vec<SecretKey>) {
    let receiver = Receiver::<(
        Sender<VaultRequest<ExtraErgoData>>,
        Receiver<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>,
    )>::connect(path)
    .await
    .unwrap();
    let (cd_send, cd_recv) = receiver.recv().await.unwrap();

    let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
    let address = encoder
        .parse_address_from_str("9hVmDmyrLoNAupFVoobZRCfbwDWnAvCmjT1KCS4yGy3XziaCyMg")
        .unwrap();

    let mut synced = false;
    let mut current_progress_point = None;
    let mut sent_tx_notarize_request = false;
    let mut pending_export_status = None;
    let max_miner_fee = 1000000;

    const TERM_CELL_VALUE: u64 = 700000;

    loop {
        sleep(tokio::time::Duration::from_secs(1)).await;
        if synced && !sent_tx_notarize_request && pending_export_status.is_none() {
            let proto_term_cells = vec![ProtoTermCell::from(ErgoTermCell(ErgoCell {
                ergs: BoxValue::try_from(TERM_CELL_VALUE).unwrap(),
                address: address.clone(),
                tokens: vec![],
            }))];
            let constraints = NotarizedReportConstraints {
                term_cells: proto_term_cells,
                last_progress_point: ProgressPoint {
                    chain_id: ChainId::from(0),
                    point: Point::from(100), // Dummy value, doesn't matter for this test
                },
                max_tx_size: Kilobytes(5.0),
                estimated_number_of_byzantine_nodes: 0,
            };

            cd_send
                .send(VaultRequest::RequestTxsToNotarize(constraints))
                .await
                .unwrap();
            sent_tx_notarize_request = true;
        } else {
            match &pending_export_status {
                Some(status) => match status {
                    PendingExportStatus::Confirmed(report) => {
                        info!(target: "driver", "ACK CONFIRMED EXPORT TX");
                        cd_send
                            .send(VaultRequest::AcknowledgeConfirmedExportTx(
                                Box::new(report.clone()),
                                current_progress_point.clone().unwrap(),
                            ))
                            .await
                            .unwrap();
                    }
                    PendingExportStatus::Aborted(report) => {
                        info!(target: "driver", "ACK ABORTED EXPORT TX");
                        cd_send
                            .send(VaultRequest::AcknowledgeAbortedExportTx(
                                Box::new(report.clone()),
                                current_progress_point.clone().unwrap(),
                            ))
                            .await
                            .unwrap();
                    }
                    PendingExportStatus::WaitingForConfirmation(_) => {
                        cd_send
                            .send(VaultRequest::SyncFrom(current_progress_point.clone()))
                            .await
                            .unwrap();
                    }
                },

                None => {
                    cd_send
                        .send(VaultRequest::SyncFrom(current_progress_point.clone()))
                        .await
                        .unwrap();
                }
            }
        }
        let VaultResponse { status, messages } = cd_recv.recv().await.unwrap();

        pending_export_status = status.get_pending_export_status();

        // `status` also describes the state of the export TX
        info!(target: "driver", "status: {:?}", status);

        for msg in messages {
            match msg {
                VaultMsgOut::MovedValue(mv) => match mv {
                    MovedValue::Applied(uv) => {
                        current_progress_point = Some(uv.progress_point);
                    }
                    MovedValue::Unapplied(uv) => {
                        current_progress_point = Some(uv.progress_point);
                    }
                },
                VaultMsgOut::ProposedTxsToNotarize(bounds) => {
                    info!(target: "driver", "notarization bounds: {:?}", bounds);
                    let vault_utxos: Vec<_> = bounds.vault_utxos.into();
                    assert_eq!(bounds.terminal_cell_bound, 1);

                    let value_to_export = vec![ErgoTermCell(ErgoCell {
                        ergs: BoxValue::try_from(TERM_CELL_VALUE).unwrap(),
                        address: address.clone(),
                        tokens: vec![],
                    })];

                    let inputs = simulate_signature_aggregation_notarized_proofs(
                        participant_secret_keys.clone(),
                        value_to_export.clone(),
                        0,
                        Threshold { num: 4, denom: 4 },
                        max_miner_fee,
                    );

                    let extra_ergo_data = ExtraErgoData {
                        starting_avl_tree: inputs.starting_avl_tree,
                        proof: inputs.proof,
                        max_miner_fee,
                        threshold: inputs.threshold,
                        vault_utxos: vault_utxos.clone(),
                    };

                    let certificate = ReportCertificate::SchnorrK256(AggregateCertificate {
                        message_digest: blake2b256_hash(&inputs.resulting_digest),
                        aggregate_commitment: inputs.aggregate_commitment,
                        aggregate_response: inputs.aggregate_response,
                        exclusion_set: inputs.exclusion_set,
                    });

                    let value_to_export = value_to_export
                        .into_iter()
                        .take(bounds.terminal_cell_bound)
                        .map(TermCell::from)
                        .collect();
                    let notarized_report = NotarizedReport {
                        certificate,
                        value_to_export,
                        authenticated_digest: inputs.resulting_digest,
                        additional_chain_data: extra_ergo_data,
                    };

                    // Note: by sending this message the driver is going to send 2 requests
                    // before getting a response, which is not how the protocol is supposed
                    // to work. We should be robust against this situation though.
                    info!(target: "driver", "Sending request to export value");
                    cd_send
                        .send(VaultRequest::ExportValue(Box::new(notarized_report)))
                        .await
                        .unwrap();
                }
            }
        }
        if let VaultStatus::Synced { .. } = status {
            synced = true;
        }
    }
}

struct AppConfig {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    chain_sync_starting_height: u32,
    export_tx_retry_config: ExportTxRetryConfig,
    log4rs_yaml_path: String,
    withdrawals_store_db_path: String,
    vault_boxes_store_db_path: String,
    moved_value_history_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<EcPoint>,
    /// NOTE: in practice secret keys shouldn't be here. It's just convenient to spawn the mock
    /// driver as a separate async process. To be removed.
    committee_secret_keys: Vec<k256::SecretKey>,
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
    export_tx_retry_config: ExportTxRetryConfig,
    log4rs_yaml_path: String,
    withdrawals_store_db_path: String,
    vault_boxes_store_db_path: String,
    moved_value_history_db_path: String,
    chain_cache_db_path: String,
    unix_socket_path: String,
    committee_public_keys: Vec<String>,
    committee_secret_keys: Vec<String>,
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
        let committee_secret_keys = value
            .committee_secret_keys
            .into_iter()
            .map(|sk_str| {
                let bytes = base16::decode(&sk_str).unwrap();
                k256::SecretKey::from_slice(&bytes).unwrap()
            })
            .collect();
        Self {
            node_addr: value.node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            chain_sync_starting_height: value.chain_sync_starting_height,
            export_tx_retry_config: value.export_tx_retry_config,
            log4rs_yaml_path: value.log4rs_yaml_path,
            withdrawals_store_db_path: value.withdrawals_store_db_path,
            vault_boxes_store_db_path: value.vault_boxes_store_db_path,
            moved_value_history_db_path: value.moved_value_history_db_path,
            chain_cache_db_path: value.chain_cache_db_path,
            unix_socket_path: value.unix_socket_path,
            committee_public_keys,
            committee_secret_keys,
            committee_box_ids: value.committee_box_ids,
            committee_guarding_script,
            vault_utxo_token_id: value.vault_utxo_token_id,
        }
    }
}

#[serde_with::serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExportTxRetryConfig {
    db_path: String,
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
