use crate::rocksdb::{serialize_tx, Block, ChainCacheRocksDB, RocksConfig};
use pallas_network::{
    facades::PeerClient,
    miniprotocols::{
        chainsync::{self, NextResponse},
        Point,
    },
};
use pallas_traverse::{MultiEraBlock, MultiEraHeader};
use spectrum_chain_connector::{DataBridge, DataBridgeComponents, TxEvent};

mod rocksdb;

pub struct CardanoDataBridge {
    pub receiver: tokio::sync::mpsc::Receiver<TxEvent<Vec<u8>>>,
    tx_start: tokio::sync::oneshot::Sender<()>,
}

impl DataBridge for CardanoDataBridge {
    type TxType = Vec<u8>;

    fn get_components(self) -> DataBridgeComponents<Self::TxType> {
        DataBridgeComponents {
            receiver: self.receiver,
            start_signal: self.tx_start,
        }
    }
}

pub struct CardanoDataBridgeConfig {
    pub chain_sync_starting_block_slot: u64,
    pub chain_sync_starting_block_hash_hex: String,
    pub node_addr: String,
    pub rocks_config: RocksConfig,
}

impl CardanoDataBridge {
    pub fn new(config: CardanoDataBridgeConfig) -> Self {
        let (tx, receiver) = tokio::sync::mpsc::channel(16);
        let (tx_start, rx_start) = tokio::sync::oneshot::channel();

        tokio::spawn(run_bridge(tx, rx_start, config));

        CardanoDataBridge { receiver, tx_start }
    }
}

async fn run_bridge(
    tx: tokio::sync::mpsc::Sender<TxEvent<Vec<u8>>>,
    rx_start: tokio::sync::oneshot::Receiver<()>,
    config: CardanoDataBridgeConfig,
) {
    // Wait for signal to start
    rx_start.await.unwrap();

    let CardanoDataBridgeConfig {
        node_addr,
        chain_sync_starting_block_slot,
        chain_sync_starting_block_hash_hex,
        rocks_config,
    } = config;

    let mut peer = PeerClient::connect(&node_addr, 2).await.unwrap();
    let client = peer.chainsync();

    let known_point = Point::Specific(
        chain_sync_starting_block_slot,
        hex::decode(chain_sync_starting_block_hash_hex).unwrap(),
    );

    let mut chain_cache = ChainCacheRocksDB::new(rocks_config);
    let start_point = if let Some(best_block) = chain_cache.get_best_block().await {
        if best_block.slot > known_point.slot_or_default() {
            Point::Specific(best_block.slot, best_block.id.to_vec())
        } else {
            known_point
        }
    } else {
        known_point
    };
    let (point, _) = client.find_intersect(vec![start_point.clone()]).await.unwrap();

    assert!(matches!(client.state(), chainsync::State::Idle));
    assert_eq!(point, Some(start_point.clone()));

    let next = client.request_next().await.unwrap();

    match next {
        NextResponse::RollBackward(point, _) => assert_eq!(point, start_point),
        _ => panic!("expected rollback"),
    }

    let mut blockfetch_peer = PeerClient::connect(&node_addr, 2).await.unwrap();
    let blockfetch_client = blockfetch_peer.blockfetch();

    while let Ok(next_response) = client.request_next().await {
        match next_response {
            NextResponse::RollForward(h, _) => {
                // Tag and subtag arguments are inferred from `HeaderContent`. I couldn't find any
                // CDDL documentation about this though.
                let header =
                    MultiEraHeader::decode(h.variant, h.byron_prefix.map(|(a, _)| a), &h.cbor).unwrap();

                let hash = header.hash();
                let next_point = Point::Specific(header.slot(), hash.to_vec());
                let block_bytes = blockfetch_client.fetch_single(next_point).await.unwrap();
                let multi_era_block = MultiEraBlock::decode(&block_bytes).expect("block");
                let transactions: Vec<Vec<u8>> = multi_era_block.txs().iter().map(serialize_tx).collect();
                let block = Block {
                    id: multi_era_block.hash(),
                    parent_id: multi_era_block.header().previous_hash().unwrap(),
                    slot: multi_era_block.slot(),
                    block_number: multi_era_block.number(),
                    transactions: transactions.clone(),
                };
                chain_cache.append_block(block).await;
                for transaction in transactions {
                    tx.send(TxEvent::AppliedTx(transaction)).await.unwrap();
                }
            }
            NextResponse::RollBackward(point, _) => {
                if let Point::Specific(slot, bytes) = point {
                    while let Some(best_block) = chain_cache.get_best_block().await {
                        assert!(best_block.slot <= slot);
                        if best_block.slot == slot {
                            assert_eq!(best_block.id.as_slice(), &bytes);
                            break;
                        } else {
                            let block = chain_cache.take_best_block().await.unwrap();
                            for transaction in block.transactions {
                                tx.send(TxEvent::UnappliedTx(transaction)).await.unwrap();
                            }
                        }
                    }
                } else {
                    panic!("Rollback to origin!");
                }
            }
            NextResponse::Await => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use pallas_network::facades::PeerClient;
    use pallas_network::miniprotocols::{
        blockfetch,
        chainsync::{self, NextResponse},
        Point,
    };
    use pallas_primitives::babbage::MintedBlock;
    use pallas_traverse::{MultiEraBlock, MultiEraHeader};
    use rand::RngCore;
    use spectrum_chain_connector::{DataBridge, DataBridgeComponents, TxEvent};

    use crate::rocksdb::{deserialize_tx, RocksConfig};
    use crate::{CardanoDataBridge, CardanoDataBridgeConfig};

    type BlockWrapper<'b> = (u16, MintedBlock<'b>);

    #[tokio::test]
    async fn test_cardano_bridge() {
        let rnd = rand::thread_rng().next_u32();
        let config = CardanoDataBridgeConfig {
            node_addr: "88.99.59.114:6000".into(),
            chain_sync_starting_block_slot: 23040684,
            chain_sync_starting_block_hash_hex:
                "6014856061f3a40c3ae2ddecbbfe46555ee0ecf9a5d2370e6057825e07100602".into(),
            rocks_config: RocksConfig {
                db_path: format!("./tmp/{}", rnd),
                max_rollback_depth: 50,
            },
        };

        let bridge = CardanoDataBridge::new(config);
        let DataBridgeComponents {
            mut receiver,
            start_signal,
        } = bridge.get_components();

        start_signal.send(()).unwrap();
        for _ in 0..10 {
            let tx = receiver.recv().await.unwrap();
            match tx {
                TxEvent::AppliedTx(bytes) => {
                    let transaction = deserialize_tx(&bytes);
                    println!("AppliedTx: {:?}", transaction.hash());
                }
                TxEvent::UnappliedTx(bytes) => {
                    let transaction = deserialize_tx(&bytes);
                    println!("UnappliedTx: {:?}", transaction.hash());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_pallas_chain_sync() {
        let mut peer = PeerClient::connect("88.99.59.114:6000", 2).await.unwrap();

        let client = peer.chainsync();

        let known_point = Point::Specific(
            23040684,
            hex::decode("6014856061f3a40c3ae2ddecbbfe46555ee0ecf9a5d2370e6057825e07100602").unwrap(),
        );

        let (point, _) = client.find_intersect(vec![known_point.clone()]).await.unwrap();

        assert!(matches!(client.state(), chainsync::State::Idle));
        assert_eq!(point, Some(known_point.clone()));

        let next = client.request_next().await.unwrap();

        match next {
            NextResponse::RollBackward(point, _) => assert_eq!(point, known_point),
            _ => panic!("expected rollback"),
        }

        assert!(matches!(client.state(), chainsync::State::Idle));

        let mut points = vec![];
        for _ in 0..30 {
            let next = client.request_next().await.unwrap();

            match next {
                NextResponse::RollForward(h, _) => {
                    let header =
                        MultiEraHeader::decode(h.variant, h.byron_prefix.map(|(a, _)| a), &h.cbor).unwrap();

                    let hash = header.hash();
                    println!(
                        "({}, hash: {:?}, prev_hash: {:?})",
                        header.slot(),
                        hash,
                        header.previous_hash()
                    );
                    let next_point = Point::Specific(header.slot(), hash.to_vec());
                    points.push(next_point);
                }
                _ => panic!("expected roll-forward"),
            }

            assert!(matches!(client.state(), chainsync::State::Idle));
        }

        let mut blockfetch_peer = PeerClient::connect("88.99.59.114:6000", 2).await.unwrap();
        let blockfetch_client = blockfetch_peer.blockfetch();

        let _res = blockfetch_client
            .request_range((points.first().unwrap().clone(), points.last().unwrap().clone()))
            .await;
        println!("GET BLOCKS -----------------");
        let mut ix = 0;
        let mut block_bytes = vec![];
        while let Ok(Some(next_block_bytes)) = blockfetch_client.recv_while_streaming().await {
            block_bytes.push(next_block_bytes.clone());
            let block = MultiEraBlock::decode(&next_block_bytes).expect("block");
            let points_hash = if let Point::Specific(_, ref hash_bytes) = points[ix] {
                hash_bytes.clone()
            } else {
                panic!("Expected Point::Specific");
            };
            assert_eq!(block.hash().to_vec(), points_hash);

            println!("{:?}, # TXs: {}", block.hash(), block.tx_count());
            ix += 1;
        }
        let blocks_serialized_bytes = bincode::serialize(&block_bytes).unwrap();
        tokio::fs::write("blocks.bin", base16::encode_lower(&blocks_serialized_bytes))
            .await
            .unwrap();
        blockfetch_client.send_done().await.unwrap();
        client.send_done().await.unwrap();

        assert!(matches!(client.state(), chainsync::State::Done));
    }

    #[tokio::test]
    async fn test_pallas_block() {
        let mut peer = PeerClient::connect("88.99.59.114:6000", 2).await.unwrap();
        let client = peer.blockfetch();

        let known_point = Point::Specific(
            23040684,
            hex::decode("6014856061f3a40c3ae2ddecbbfe46555ee0ecf9a5d2370e6057825e07100602").unwrap(),
        );

        let range_ok = client.request_range((known_point.clone(), known_point)).await;

        assert!(matches!(client.state(), blockfetch::State::Streaming));

        println!("streaming...");

        assert!(matches!(range_ok, Ok(_)));

        for _ in 0..1 {
            let next = client.recv_while_streaming().await.unwrap();

            match next {
                Some(body) => {
                    let (i, block) = pallas_codec::minicbor::decode::<BlockWrapper>(&body).expect("babbage");
                    println!("({}, {:?})", i, block);
                }
                _ => panic!("expected block body"),
            }

            assert!(matches!(client.state(), blockfetch::State::Streaming));
        }

        let next = client.recv_while_streaming().await.unwrap();

        assert!(matches!(next, None));

        client.send_done().await.unwrap();

        assert!(matches!(client.state(), blockfetch::State::Done));
    }
}
