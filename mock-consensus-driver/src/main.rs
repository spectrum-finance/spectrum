use clap::Parser;
use std::path::PathBuf;

use crate::app::App;
use ergo_lib::ergotree_ir::chain::{
    address::{AddressEncoder, NetworkPrefix},
    ergo_box::box_value::BoxValue,
};
use k256::SecretKey;
use log::info;
use serde::Deserialize;
use spectrum_chain_connector::{
    Kilobytes, MovedValue, NotarizedReport, NotarizedReportConstraints, PendingExportStatus, ProtoTermCell,
    VaultMsgOut, VaultRequest, VaultResponse, VaultStatus,
};
use spectrum_crypto::digest::blake2b256_hash;
use spectrum_ergo_connector::{
    rocksdb::vault_boxes::ErgoNotarizationBounds,
    script::{simulate_signature_aggregation_notarized_proofs, ErgoCell, ErgoTermCell, ExtraErgoData},
};
use spectrum_handel::Threshold;
use spectrum_ledger::{
    cell::{ProgressPoint, TermCell},
    interop::{Point, ReportCertificate},
    ChainId,
};
use spectrum_sigma::sigma_aggregation::AggregateCertificate;
use tokio::sync::mpsc::channel;
use tokio::time::sleep;
use tokio_unix_ipc::{Receiver, Sender};

mod action;
mod app;
mod components;
mod config;
mod event;
mod mode;
mod tui;

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
    let (tx, rx) = channel(50);
    let mut app = App::new(2.0, 4.0).unwrap();

    tokio::spawn(mock_consensus_driver(
        config.unix_socket_path.into(),
        config.committee_secret_keys,
        tx,
    ));
    app.run(rx).await.unwrap();
}

async fn mock_consensus_driver(
    path: PathBuf,
    participant_secret_keys: Vec<SecretKey>,
    tx: tokio::sync::mpsc::Sender<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>,
) {
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
        let resp = cd_recv.recv().await.unwrap();
        tx.send(resp.clone()).await.unwrap();
        let VaultResponse { status, messages } = resp;

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
    unix_socket_path: String,
    committee_secret_keys: Vec<k256::SecretKey>,
    log4rs_yaml_path: String,
}
#[derive(Deserialize)]
struct AppConfigProto {
    unix_socket_path: String,
    committee_secret_keys: Vec<String>,
    log4rs_yaml_path: String,
}

impl From<AppConfigProto> for AppConfig {
    fn from(value: AppConfigProto) -> Self {
        let committee_secret_keys = value
            .committee_secret_keys
            .into_iter()
            .map(|sk_str| {
                let bytes = base16::decode(&sk_str).unwrap();
                k256::SecretKey::from_slice(&bytes).unwrap()
            })
            .collect();
        Self {
            unix_socket_path: value.unix_socket_path,
            committee_secret_keys,
            log4rs_yaml_path: value.log4rs_yaml_path,
        }
    }
}

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Spectrum Finance Mock Consensus driver", long_about = None)]
struct AppArgs {
    /// Path to the YAML configuration file.
    #[arg(long, short)]
    config_path: String,
    /// Optional path to the log4rs YAML configuration file. NOTE: overrides path specified in config YAML file.
    #[arg(long, short)]
    log4rs_path: Option<String>,
}
