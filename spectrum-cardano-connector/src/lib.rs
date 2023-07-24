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

    type BlockWrapper<'b> = (u16, MintedBlock<'b>);
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
        for _ in 0..5 {
            let next = client.request_next().await.unwrap();

            match next {
                NextResponse::RollForward(h, _) => {
                    // Tag and subtag arguments are inferred from
                    // `HeaderContent`. I couldn't find any CDDL documentation
                    // about this though.
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
        while let Ok(Some(next_block_bytes)) = blockfetch_client.recv_while_streaming().await {
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
                    //assert_eq!(body.len(), 3251);
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
