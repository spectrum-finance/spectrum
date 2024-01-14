use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use crate::app::App;
use ergo_lib::ergotree_ir::chain::address::Address;
use ergo_lib::ergotree_ir::chain::{
    address::{AddressEncoder, NetworkPrefix},
    ergo_box::box_value::BoxValue,
};
use k256::SecretKey;
use log::info;
use serde::Deserialize;
use spectrum_chain_connector::{
    ChainTxEvent, InboundValue, Kilobytes, NotarizedReport, NotarizedReportConstraints, PendingDepositStatus,
    PendingExportStatus, PendingTxIdentifier, PendingTxStatus, ProtoTermCell, SpectrumTx, SpectrumTxType,
    TxStatus, VaultMsgOut, VaultRequest, VaultResponse, VaultStatus,
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
use spectrum_offchain_lm::prover::{SeedPhrase, Wallet};
use spectrum_sigma::sigma_aggregation::AggregateCertificate;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
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

    let seed_phrases = config
        .wallet_seed_phrases
        .into_iter()
        .map(SeedPhrase::from)
        .collect();

    let mut driver = MockConsensusDriver::new(
        config.unix_socket_path.into(),
        config.committee_secret_keys,
        seed_phrases,
        tx,
        1,
    );

    let wrapped = Arc::new(Mutex::new(driver));
    let cloned = wrapped.clone();
    tokio::spawn(async move { cloned.lock().await.run().await });
    app.run(rx).await.unwrap();
}

struct MockConsensusDriver {
    vault_manager_status: Option<VaultStatus<ExtraErgoData>>,
    pending_tx_status: Option<PendingTxStatus<ExtraErgoData>>,
    unprocessed_deposits: Vec<InboundValue>,
    unix_socket_path: PathBuf,
    committee_secret_keys: Vec<SecretKey>,
    frontend_tx: tokio::sync::mpsc::Sender<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>,
    tick_delay_in_seconds: u64,
    user_wallets: Vec<(Wallet, Address)>,
    proposed_withdrawal_term_cells: Option<Vec<ProtoTermCell>>,
}

impl MockConsensusDriver {
    fn new(
        unix_socket_path: PathBuf,
        committee_secret_keys: Vec<SecretKey>,
        seed_phrases: Vec<SeedPhrase>,
        frontend_tx: tokio::sync::mpsc::Sender<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>,
        tick_delay_in_seconds: u64,
    ) -> Self {
        let user_wallets = seed_phrases
            .into_iter()
            .map(|phrase| Wallet::try_from_seed(phrase).unwrap())
            .collect();
        Self {
            vault_manager_status: None,
            pending_tx_status: None,
            unprocessed_deposits: vec![],
            unix_socket_path,
            committee_secret_keys,
            frontend_tx,
            tick_delay_in_seconds,
            user_wallets,
            proposed_withdrawal_term_cells: None,
        }
    }

    async fn run(&mut self) {
        let receiver = Receiver::<(
            Sender<VaultRequest<ExtraErgoData>>,
            Receiver<VaultResponse<ExtraErgoData, ErgoNotarizationBounds>>,
        )>::connect(self.unix_socket_path.clone())
        .await
        .unwrap();
        let (unix_sock_tx, unix_sock_rx) = receiver.recv().await.unwrap();

        loop {
            sleep(tokio::time::Duration::from_secs(self.tick_delay_in_seconds)).await;

            // Send a request to the vault-manager
            match &self.pending_tx_status {
                None => match &self.vault_manager_status {
                    Some(VaultStatus::Synced {
                        current_progress_point,
                        ..
                    }) => {
                        // TODO: if received withdrawal or deposit action from frontend, put it through
                    }
                    Some(VaultStatus::Syncing {
                        current_progress_point,
                        ..
                    }) => {
                        unix_sock_tx
                            .send(VaultRequest::SyncFrom(Some(current_progress_point.clone())))
                            .await
                            .unwrap();
                    }
                    None => {
                        unix_sock_tx.send(VaultRequest::SyncFrom(None)).await.unwrap();
                    }
                },

                Some(status) => match status {
                    PendingTxStatus::Export(PendingExportStatus {
                        identifier: data,
                        status,
                    }) => match status {
                        TxStatus::Confirmed => {
                            info!(target: "driver", "ACK CONFIRMED EXPORT TX");
                            unix_sock_tx
                                .send(VaultRequest::AcknowledgeConfirmedTx(
                                    PendingTxIdentifier::Export(Box::new(data.clone())),
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point())
                                        .unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::Aborted => {
                            info!(target: "driver", "ACK ABORTED EXPORT TX");
                            unix_sock_tx
                                .send(VaultRequest::AcknowledgeAbortedTx(
                                    PendingTxIdentifier::Export(Box::new(data.clone())),
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point())
                                        .unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::WaitingForConfirmation => {
                            unix_sock_tx
                                .send(VaultRequest::SyncFrom(
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point()),
                                ))
                                .await
                                .unwrap();
                        }
                    },
                    PendingTxStatus::Deposit(PendingDepositStatus {
                        identifier: data,
                        status,
                    }) => match status {
                        TxStatus::WaitingForConfirmation => {
                            unix_sock_tx
                                .send(VaultRequest::SyncFrom(
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point()),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::Confirmed => {
                            info!(target: "driver", "ACK CONFIRMED DEPOSIT TX");
                            unix_sock_tx
                                .send(VaultRequest::AcknowledgeConfirmedTx(
                                    PendingTxIdentifier::Deposit(data.clone()),
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point())
                                        .unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::Aborted => {
                            info!(target: "driver", "ACK ABORTED DEPOSIT TX");
                            unix_sock_tx
                                .send(VaultRequest::AcknowledgeAbortedTx(
                                    PendingTxIdentifier::Deposit(data.clone()),
                                    self.vault_manager_status
                                        .clone()
                                        .map(|status| status.get_current_progress_point())
                                        .unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                    },
                },
            }

            // Get response from vault manager.
            let resp = unix_sock_rx.recv().await.unwrap();
            self.frontend_tx.send(resp.clone()).await.unwrap();
            let VaultResponse { status, messages } = resp;

            self.pending_tx_status = status.get_pending_tx_status();
            self.vault_manager_status = Some(status);

            for msg in messages {
                match msg {
                    VaultMsgOut::MovedValue(mv) => match mv {
                        ChainTxEvent::Applied(SpectrumTx {
                            progress_point,
                            tx_type,
                        }) => match tx_type {
                            SpectrumTxType::Deposit { imported_value } => {
                                for inbound_value in imported_value {
                                    assert!(!self.unprocessed_deposits.contains(&inbound_value));
                                    self.unprocessed_deposits.push(inbound_value);
                                }
                            }
                            SpectrumTxType::Withdrawal { exported_value } => {}
                        },
                        ChainTxEvent::Unapplied(_) => {
                            // TODO
                        }
                    },
                    VaultMsgOut::ProposedTxsToNotarize(bounds) => {
                        info!(target: "driver", "notarization bounds: {:?}", bounds);
                        let vault_utxos: Vec<_> = bounds.vault_utxos.into();
                        let term_cells = self.proposed_withdrawal_term_cells.take().unwrap();
                        assert_eq!(bounds.terminal_cell_bound, 1);

                        let value_to_export: Vec<ErgoTermCell> = term_cells
                            .iter()
                            .map(|p| ErgoTermCell(ErgoCell::from(p)))
                            .collect();

                        let max_miner_fee = 1000000;

                        let inputs = simulate_signature_aggregation_notarized_proofs(
                            self.committee_secret_keys.clone(),
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
                        unix_sock_tx
                            .send(VaultRequest::ExportValue(Box::new(notarized_report)))
                            .await
                            .unwrap();
                    }

                    VaultMsgOut::GenesisVaultUtxo(value) => (),
                }
            }
        }
    }
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
                    PendingTxStatus::Export(PendingExportStatus {
                        identifier: data,
                        status,
                    }) => match status {
                        TxStatus::Confirmed => {
                            info!(target: "driver", "ACK CONFIRMED EXPORT TX");
                            cd_send
                                .send(VaultRequest::AcknowledgeConfirmedTx(
                                    PendingTxIdentifier::Export(Box::new(data.clone())),
                                    current_progress_point.clone().unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::Aborted => {
                            info!(target: "driver", "ACK ABORTED EXPORT TX");
                            cd_send
                                .send(VaultRequest::AcknowledgeAbortedTx(
                                    PendingTxIdentifier::Export(Box::new(data.clone())),
                                    current_progress_point.clone().unwrap(),
                                ))
                                .await
                                .unwrap();
                        }
                        TxStatus::WaitingForConfirmation => {
                            cd_send
                                .send(VaultRequest::SyncFrom(current_progress_point.clone()))
                                .await
                                .unwrap();
                        }
                    },
                    PendingTxStatus::Deposit(PendingDepositStatus {
                        identifier: data,
                        status,
                    }) => match status {
                        TxStatus::WaitingForConfirmation => {}
                        TxStatus::Confirmed => {}
                        TxStatus::Aborted => {}
                    },
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

        pending_export_status = status.get_pending_tx_status();

        // `status` also describes the state of the export TX
        info!(target: "driver", "status: {:?}", status);

        for msg in messages {
            match msg {
                VaultMsgOut::MovedValue(mv) => match mv {
                    ChainTxEvent::Applied(uv) => {
                        current_progress_point = Some(uv.progress_point);
                    }
                    ChainTxEvent::Unapplied(uv) => {
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
                VaultMsgOut::GenesisVaultUtxo(_) => (),
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
    wallet_seed_phrases: Vec<String>,
}
#[derive(Deserialize)]
struct AppConfigProto {
    unix_socket_path: String,
    committee_secret_keys: Vec<String>,
    log4rs_yaml_path: String,
    wallet_seed_phrases: Vec<String>,
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
            wallet_seed_phrases: value.wallet_seed_phrases,
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
