use std::fmt::Debug;
use std::{sync::Arc, time::Duration};

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use chrono::Utc;
use ergo_lib::{chain::transaction::Input, ergotree_ir::chain::ergo_box::ErgoBox};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{NotarizedReport, PendingExportStatus};

use crate::script::ExtraErgoData;

/// Handle resubmission of Spectrum Network TXs.
#[async_trait(?Send)]
pub trait TxRetryScheduler<T, U>
where
    T: Has<U>,
{
    /// To be called when connector has submitted export TX to mempool.
    async fn add(&mut self, data: T);
    /// Obtain next command from the scheduler
    async fn next_command(&self) -> Command<T>;
    async fn notify_confirmed(&mut self, data: &T);
    async fn notify_failed(&mut self, export: &T);
    async fn clear_confirmed(&mut self, element: &U);
    async fn clear_aborted(&mut self, element: &U);
}

trait Has<T> {
    fn has(&self, t: &T) -> bool;
}

trait Timestamped {
    fn get_timestamp(&self) -> i64;
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
impl<'a, T, U> TxRetryScheduler<T, U> for ExportTxRetrySchedulerRocksDB
where
    T: Has<U> + Timestamped + Clone + Debug + Eq + Serialize + DeserializeOwned + Send + Sync + 'static,
    U: Clone + Debug + Send + Sync + 'static,
{
    async fn add(&mut self, data: T) {
        let db = Arc::clone(&self.db);
        let retry_delay_duration = self.retry_delay_duration;
        spawn_blocking(move || {
            let value_bytes = rmp_serde::to_vec_named(&data).unwrap();
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
                (data.get_timestamp() + retry_delay_duration).to_be_bytes(),
            )
            .unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    async fn next_command(&self) -> Command<T> {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || match db.get(EXPORT_KEY.as_bytes()).unwrap() {
            Some(value_bytes) => {
                let status_bytes = db.get(STATUS_KEY.as_bytes()).unwrap().unwrap();
                let status: Status = rmp_serde::from_slice(&status_bytes).unwrap();
                let export: T = rmp_serde::from_slice(&value_bytes).unwrap();
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

    async fn notify_confirmed(&mut self, export: &T) {
        let db = Arc::clone(&self.db);
        let cloned = export.clone();
        spawn_blocking(move || {
            let value_bytes = db.get(EXPORT_KEY.as_bytes()).unwrap().unwrap();
            let value: T = rmp_serde::from_slice(&value_bytes).unwrap();
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

    async fn notify_failed(&mut self, data: &T) {
        let db = Arc::clone(&self.db);
        let cloned = data.clone();
        let max_retries = self.max_retries;
        spawn_blocking(move || {
            let value_bytes = db.get(EXPORT_KEY.as_bytes()).unwrap().unwrap();
            let value: T = rmp_serde::from_slice(&value_bytes).unwrap();
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

    async fn clear_confirmed(&mut self, element: &U) {
        let db = Arc::clone(&self.db);
        let cloned = element.clone();
        spawn_blocking(move || {
            if let Some(value_bytes) = db.get(EXPORT_KEY.as_bytes()).unwrap() {
                let value: T = rmp_serde::from_slice(&value_bytes).unwrap();
                assert!(value.has(&cloned));
                let status_bytes = db.get(STATUS_KEY.as_bytes()).unwrap().unwrap();
                let status: Status = rmp_serde::from_slice(&status_bytes).unwrap();
                assert_eq!(status, Status::Confirmed);
                db.delete(EXPORT_KEY.as_bytes()).unwrap();
            }
        })
        .await
    }

    async fn clear_aborted(&mut self, element: &U) {
        let db = Arc::clone(&self.db);
        let cloned = element.clone();
        spawn_blocking(move || {
            if let Some(value_bytes) = db.get(EXPORT_KEY.as_bytes()).unwrap() {
                let value: T = rmp_serde::from_slice(&value_bytes).unwrap();
                assert!(value.has(&cloned));
                let status_bytes = db.get(STATUS_KEY.as_bytes()).unwrap().unwrap();
                let status: Status = rmp_serde::from_slice(&status_bytes).unwrap();
                assert_eq!(status, Status::Aborted);
                db.delete(EXPORT_KEY.as_bytes()).unwrap();
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
pub enum Command<T> {
    /// Resubmit the export Tx.
    ResubmitTx(T),
    /// Give up trying to submit the Tx.
    Abort(T),
    /// Wait for the specified duration to retry export Tx
    Wait(Duration, T),
    /// Current export has been confirmed
    Confirmed(T),
    /// There's currently no export in progress
    Idle,
}

impl From<Command<ExportInProgress>> for Option<PendingExportStatus<ExtraErgoData>> {
    fn from(value: Command<ExportInProgress>) -> Self {
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

impl Has<NotarizedReport<ExtraErgoData>> for ExportInProgress {
    fn has(&self, t: &NotarizedReport<ExtraErgoData>) -> bool {
        self.report == *t
    }
}

impl Timestamped for ExportInProgress {
    fn get_timestamp(&self) -> i64 {
        self.timestamp
    }
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
        rocksdb::tx_retry_scheduler::{Command, TxRetryScheduler},
        script::{dummy_resolver, ExtraErgoData},
    };

    use super::{ExportInProgress, ExportTxRetrySchedulerRocksDB};

    #[tokio::test]
    async fn test_confirmed_export() {
        let mut client = rocks_db_client(10).await;
        let export = make_dummy_export();
        let idle: Command<crate::rocksdb::tx_retry_scheduler::ExportInProgress> = Command::Idle;
        assert_eq!(idle, client.next_command().await);
        client.add(export).await;
        let Command::Wait(_, exp): Command<ExportInProgress> = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_confirmed(&exp).await;
        assert_eq!(Command::Confirmed(exp.clone()), client.next_command().await);
    }

    #[tokio::test]
    async fn test_failed_export() {
        let mut client = rocks_db_client(10).await;
        let export = make_dummy_export();
        let idle: Command<crate::rocksdb::tx_retry_scheduler::ExportInProgress> = Command::Idle;
        assert_eq!(idle, client.next_command().await);
        client.add(export.clone()).await;
        client.notify_failed(&export).await;
        let Command::Wait(_, exp): Command<ExportInProgress> = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_failed(&exp).await;
        let Command::Wait(_, exp): Command<ExportInProgress> = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        client.notify_failed(&exp).await;
        assert_eq!(Command::Abort(exp.clone()), client.next_command().await);
    }

    #[tokio::test]
    async fn test_delays() {
        let mut client = rocks_db_client(1).await;
        let export = make_dummy_export();
        client.add(export.clone()).await;
        let Command::Wait(d, exp): Command<ExportInProgress> = client.next_command().await else {
            panic!("Expected Command::Wait");
        };
        println!("Wait {:?}", d);
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let Command::ResubmitTx(exp): Command<ExportInProgress> = client.next_command().await else {
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
