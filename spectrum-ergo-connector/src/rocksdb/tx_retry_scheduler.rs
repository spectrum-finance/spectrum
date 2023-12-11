use std::{sync::Arc, time::Duration};

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use chrono::Utc;
use ergo_lib::{chain::transaction::Input, ergotree_ir::chain::ergo_box::ErgoBox};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{NotarizedReport, PendingExportStatus};

use crate::script::ExtraErgoData;

#[async_trait(?Send)]
pub trait ExportTxRetryScheduler {
    /// To be called when connector has submitted export TX to mempool.
    async fn add_new_export(&mut self, export: ExportInProgress);
    /// Obtain next command from the scheduler
    async fn next_command(&self) -> Command;
    async fn notify_confirmed(&mut self, export: &ExportInProgress);
    async fn notify_failed(&mut self, export: &ExportInProgress);
}

pub struct ExportTxRetrySchedulerRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
    retry_delay_duration: i64,
    max_retries: u32,
}

impl ExportTxRetrySchedulerRocksDB {
    pub async fn new(db_path: &str, retry_delay_duration: i64, max_retries: u32) -> Self {
        let res = Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
            retry_delay_duration,
            max_retries,
        };
        let db = Arc::clone(&res.db);
        spawn_blocking(move || {
            db.put(COUNT_KEY.as_bytes(), 0_u32.to_be_bytes()).unwrap();
        })
        .await;

        res
    }
}

#[async_trait(?Send)]
impl ExportTxRetryScheduler for ExportTxRetrySchedulerRocksDB {
    async fn add_new_export(&mut self, export: ExportInProgress) {
        let db = Arc::clone(&self.db);
        let retry_delay_duration = self.retry_delay_duration;
        spawn_blocking(move || {
            let value_bytes = rmp_serde::to_vec_named(&export).unwrap();
            let tx = db.transaction();
            tx.put(EXPORT_KEY.as_bytes(), value_bytes).unwrap();
            tx.put(COUNT_KEY.as_bytes(), 0_u32.to_be_bytes()).unwrap();
            tx.put(
                STATUS_KEY.as_bytes(),
                rmp_serde::to_vec_named(&Status::InProgress).unwrap(),
            )
            .unwrap();
            tx.put(
                RETRY_TIMESTAMP_KEY.as_bytes(),
                (export.timestamp + retry_delay_duration).to_be_bytes(),
            )
            .unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    async fn next_command(&self) -> Command {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || match db.get(EXPORT_KEY.as_bytes()).unwrap() {
            Some(value_bytes) => {
                let status_bytes = db.get(STATUS_KEY.as_bytes()).unwrap().unwrap();
                let status: Status = rmp_serde::from_slice(&status_bytes).unwrap();
                let export: ExportInProgress = rmp_serde::from_slice(&value_bytes).unwrap();
                match status {
                    Status::InProgress => {
                        let ts_now = Utc::now().timestamp();
                        let timestamp_bytes = db.get(RETRY_TIMESTAMP_KEY.as_bytes()).unwrap().unwrap();
                        let next_timestamp = i64::from_be_bytes(timestamp_bytes.try_into().unwrap());
                        if ts_now >= next_timestamp {
                            Command::ResubmitTx(export)
                        } else {
                            Command::Wait(Duration::from_secs((next_timestamp - ts_now) as u64), export)
                        }
                    }
                    Status::Confirmed => Command::Confirmed(export),
                    Status::Aborted => Command::Abort(export),
                }
            }
            None => Command::Idle,
        })
        .await
    }

    async fn notify_confirmed(&mut self, export: &ExportInProgress) {
        let db = Arc::clone(&self.db);
        let cloned = export.clone();
        spawn_blocking(move || {
            let value_bytes = db.get(EXPORT_KEY.as_bytes()).unwrap().unwrap();
            let value: ExportInProgress = rmp_serde::from_slice(&value_bytes).unwrap();
            assert_eq!(value, cloned);
            let tx = db.transaction();
            tx.put(
                STATUS_KEY.as_bytes(),
                rmp_serde::to_vec_named(&Status::Confirmed).unwrap(),
            )
            .unwrap();
            tx.put(COUNT_KEY.as_bytes(), 0_u32.to_be_bytes()).unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    async fn notify_failed(&mut self, export: &ExportInProgress) {
        let db = Arc::clone(&self.db);
        let cloned = export.clone();
        let max_retries = self.max_retries;
        spawn_blocking(move || {
            let value_bytes = db.get(EXPORT_KEY.as_bytes()).unwrap().unwrap();
            let value: ExportInProgress = rmp_serde::from_slice(&value_bytes).unwrap();
            assert_eq!(value, cloned);
            let count_bytes = db.get(COUNT_KEY.as_bytes()).unwrap().unwrap();
            let count = u32::from_be_bytes(count_bytes.try_into().unwrap());
            db.put(COUNT_KEY.as_bytes(), (count + 1).to_be_bytes()).unwrap();
            if count + 1 == max_retries {
                db.put(
                    STATUS_KEY.as_bytes(),
                    rmp_serde::to_vec_named(&Status::Aborted).unwrap(),
                )
                .unwrap();
            }
        })
        .await
    }
}

const EXPORT_KEY: &str = "e:";
const COUNT_KEY: &str = "c:";
const RETRY_TIMESTAMP_KEY: &str = "r:";
const STATUS_KEY: &str = "s:";

#[derive(PartialEq, Eq, Debug)]
pub enum Command {
    /// Resubmit the export Tx.
    ResubmitTx(ExportInProgress),
    /// Give up trying to submit the Tx.
    Abort(ExportInProgress),
    /// Wait for the specified duration to retry export Tx
    Wait(Duration, ExportInProgress),
    /// Current export has been confirmed
    Confirmed(ExportInProgress),
    /// There's currently no export in progress
    Idle,
}

impl From<Command> for Option<PendingExportStatus<ExtraErgoData>> {
    fn from(value: Command) -> Self {
        match value {
            Command::ResubmitTx(e) | Command::Wait(_, e) => {
                Some(PendingExportStatus::WaitingForConfirmation(e.report))
            }
            Command::Abort(e) => Some(PendingExportStatus::Aborted(e.report)),
            Command::Confirmed(e) => Some(PendingExportStatus::Confirmed(e.report)),
            Command::Idle => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ExportInProgress {
    pub report: NotarizedReport<ExtraErgoData>,
    pub vault_utxo_signed_input: Input,
    pub vault_utxo: ErgoBox,
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
enum Status {
    InProgress,
    Aborted,
    Confirmed,
}

#[cfg(test)]
mod tests {

    use chrono::Utc;
    use ergo_lib::{
        chain::transaction::Input,
        ergo_chain_types::Digest,
        ergotree_ir::mir::avl_tree_data::{AvlTreeData, AvlTreeFlags},
    };
    use rand::{rngs::OsRng, RngCore};
    use scorex_crypto_avltree::{
        authenticated_tree_ops::AuthenticatedTreeOps, batch_avl_prover::BatchAVLProver, batch_node::AVLTree,
    };
    use sigma_test_util::force_any_val;
    use spectrum_chain_connector::NotarizedReport;
    use spectrum_crypto::{digest::Blake2bDigest256, pubkey::PublicKey};
    use spectrum_handel::Threshold;
    use spectrum_ledger::interop::ReportCertificate;
    use spectrum_sigma::{sigma_aggregation::AggregateCertificate, AggregateCommitment};

    use crate::{
        rocksdb::tx_retry_scheduler::{Command, ExportTxRetryScheduler},
        script::{dummy_resolver, ExtraErgoData},
    };

    use super::{ExportInProgress, ExportTxRetrySchedulerRocksDB};

    #[tokio::test]
    async fn test_confirmed_export() {
        let mut client = rocks_db_client(10).await;
        let export = make_dummy_export();
        assert_eq!(Command::Idle, client.next_command().await);
        client.add_new_export(export).await;
        let Command::Wait(_, exp) = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_confirmed(&exp).await;
        assert_eq!(Command::Confirmed(exp.clone()), client.next_command().await);
    }

    #[tokio::test]
    async fn test_failed_export() {
        let mut client = rocks_db_client(10).await;
        let export = make_dummy_export();
        assert_eq!(Command::Idle, client.next_command().await);
        client.add_new_export(export.clone()).await;
        client.notify_failed(&export).await;
        let Command::Wait(_, exp) = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_failed(&exp).await;
        let Command::Wait(_, exp) = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_failed(&exp).await;
        assert_eq!(Command::Abort(exp.clone()), client.next_command().await);
    }

    #[tokio::test]
    async fn test_delays() {
        let mut client = rocks_db_client(1).await;
        let export = make_dummy_export();
        client.add_new_export(export.clone()).await;
        let Command::Wait(d, exp) = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        println!("Wait {:?}", d);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let Command::ResubmitTx(exp) = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        assert_eq!(exp, export);
    }

    fn make_dummy_export() -> ExportInProgress {
        let empty_tree = AVLTree::new(dummy_resolver, 8, Some(32));
        let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
        let initial_digest = prover.digest().unwrap().to_vec();

        let starting_avl_tree = AvlTreeData {
            digest: Digest::<33>::try_from(initial_digest).unwrap(),
            tree_flags: AvlTreeFlags::new(true, false, false),
            key_length: 8,
            value_length_opt: Some(Box::new(32)),
        };
        let proof = prover.generate_proof().to_vec();

        let additional_chain_data = ExtraErgoData {
            starting_avl_tree,
            proof,
            max_miner_fee: 1000000,
            threshold: Threshold { num: 4, denom: 4 },
            vault_utxos: vec![],
        };

        let mut rng = OsRng;
        let aggr_certificate = AggregateCertificate {
            message_digest: Blake2bDigest256::random(),
            aggregate_commitment: AggregateCommitment::from(PublicKey::from(k256::SecretKey::random(
                &mut rng,
            ))),

            aggregate_response: k256::Scalar::ZERO,
            exclusion_set: vec![],
        };

        let report = NotarizedReport {
            certificate: ReportCertificate::SchnorrK256(aggr_certificate),
            value_to_export: vec![],
            authenticated_digest: vec![],
            additional_chain_data,
        };

        ExportInProgress {
            report,
            vault_utxo_signed_input: force_any_val::<Input>(),
            vault_utxo: force_any_val(),
            timestamp: Utc::now().timestamp(),
        }
    }

    async fn rocks_db_client(retry_delay_duration: i64) -> ExportTxRetrySchedulerRocksDB {
        let rnd = rand::thread_rng().next_u32();
        ExportTxRetrySchedulerRocksDB::new(&format!("./tmp/{}", rnd), retry_delay_duration, 3).await
    }
}
