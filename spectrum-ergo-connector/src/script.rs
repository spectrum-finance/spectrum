use scorex_crypto_avltree::{
    batch_node::{Node, NodeHeader},
    operation::Digest32,
};

fn dummy_resolver(digest: &Digest32) -> Node {
    Node::LabelOnly(NodeHeader::new(Some(digest.clone()), None))
}
#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::io::Write;

    use bytes::Bytes;
    use ergo_lib::chain::ergo_state_context::ErgoStateContext;
    use ergo_lib::chain::ergo_state_context::Headers;
    use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
    use ergo_lib::chain::transaction::TxId;
    use ergo_lib::chain::transaction::TxIoVec;
    use ergo_lib::chain::transaction::UnsignedInput;
    use ergo_lib::ergo_chain_types::ec_point::generator;
    use ergo_lib::ergo_chain_types::BlockId;
    use ergo_lib::ergo_chain_types::Digest;
    use ergo_lib::ergo_chain_types::EcPoint;
    use ergo_lib::ergo_chain_types::Header;
    use ergo_lib::ergo_chain_types::PreHeader;
    use ergo_lib::ergo_chain_types::Votes;
    use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ContextExtension;
    use ergo_lib::ergotree_ir::bigint256::BigInt256;
    use ergo_lib::ergotree_ir::chain::address::AddressEncoder;
    use ergo_lib::ergotree_ir::chain::address::NetworkPrefix;
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
    use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBoxCandidate;
    use ergo_lib::ergotree_ir::chain::ergo_box::NonMandatoryRegisterId;
    use ergo_lib::ergotree_ir::chain::ergo_box::NonMandatoryRegisters;
    use ergo_lib::ergotree_ir::mir::avl_tree_data::AvlTreeData;
    use ergo_lib::ergotree_ir::mir::avl_tree_data::AvlTreeFlags;
    use ergo_lib::ergotree_ir::mir::constant::Constant;
    use ergo_lib::ergotree_ir::mir::constant::Literal;
    use ergo_lib::ergotree_ir::mir::value::CollKind;
    use ergo_lib::ergotree_ir::serialization::sigma_byte_writer::SigmaByteWrite;
    use ergo_lib::ergotree_ir::serialization::sigma_byte_writer::SigmaByteWriter;
    use ergo_lib::ergotree_ir::sigma_protocol::dlog_group::scalar_to_bigint256;
    use ergo_lib::ergotree_ir::types::stuple::STuple;
    use ergo_lib::ergotree_ir::types::stuple::TupleItems;
    use ergo_lib::ergotree_ir::types::stype::SType;
    use ergo_lib::wallet::miner_fee::MINERS_FEE_ADDRESS;
    use ergo_lib::wallet::tx_context::TransactionContext;
    use ergo_lib::wallet::Wallet;
    use indexmap::IndexMap;
    use k256::elliptic_curve::generic_array::GenericArray;
    use k256::elliptic_curve::hash2curve::MapToCurve;
    use k256::schnorr::signature::Signer;
    use k256::schnorr::SigningKey;
    use k256::FieldElement;
    use k256::NonZeroScalar;
    use k256::ProjectivePoint;
    use k256::Scalar;
    use k256::SecretKey;
    use num256::Int256;
    use num_bigint::BigInt;
    use num_bigint::BigUint;
    use num_bigint::Sign;
    use num_bigint::ToBigUint;
    use num_traits::Bounded;
    use num_traits::Num;
    use rand::rngs::OsRng;
    use scorex_crypto_avltree::authenticated_tree_ops::*;
    use scorex_crypto_avltree::batch_avl_prover::BatchAVLProver;
    use scorex_crypto_avltree::batch_node::*;
    use scorex_crypto_avltree::operation::*;
    use sigma_ser::vlq_encode::WriteSigmaVlqExt;

    use super::dummy_resolver;

    const KEY_LENGTH: usize = 32;
    const VALUE_LENGTH: usize = 8;
    const MIN_KEY: [u8; KEY_LENGTH] = [0u8; KEY_LENGTH];
    const MAX_KEY: [u8; KEY_LENGTH] = [0xFFu8; KEY_LENGTH];

    fn random_key() -> ADKey {
        Bytes::copy_from_slice(&rand::random::<[u8; KEY_LENGTH]>())
    }

    fn random_value() -> ADValue {
        Bytes::copy_from_slice(&rand::random::<[u8; VALUE_LENGTH]>())
    }

    fn random_kv() -> KeyValue {
        loop {
            let key = random_key();
            if key != Bytes::copy_from_slice(&MIN_KEY) && key != Bytes::copy_from_slice(&MAX_KEY) {
                let value = random_value();
                return KeyValue { key, value };
            }
        }
    }
    #[test]
    fn test_avl_tree_verification() {
        let empty_tree = AVLTree::new(dummy_resolver, KEY_LENGTH, Some(VALUE_LENGTH));
        let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
        let initial_digest = prover.digest().unwrap().to_vec();
        let pairs: Vec<_> = (0..3).map(|_| random_kv()).collect();
        for kv in &pairs {
            let m = Operation::Insert(kv.clone());
            prover.perform_one_operation(&m).unwrap();
        }
        let operations_vec: Vec<_> = pairs
            .into_iter()
            .map(|kv| {
                let key_const = Literal::from(kv.key.to_vec());
                let value_const = Literal::from(kv.value.to_vec());
                Literal::Tup(TupleItems::try_from(vec![key_const, value_const]).unwrap())
            })
            .collect();

        let operations_tpe = SType::SColl(Box::new(SType::STuple(STuple::pair(
            SType::SColl(Box::new(SType::SByte)),
            SType::SColl(Box::new(SType::SByte)),
        ))));
        let operations_lit = Literal::Coll(CollKind::WrappedColl {
            elem_tpe: SType::STuple(STuple::pair(
                SType::SColl(Box::new(SType::SByte)),
                SType::SColl(Box::new(SType::SByte)),
            )),
            items: operations_vec,
        });
        let operations_const = Constant {
            tpe: operations_tpe,
            v: operations_lit,
        };

        let proof = Constant::from(prover.generate_proof().to_vec());
        let resulting_digest = prover.digest().unwrap().to_vec();
        let avl_tree_data = AvlTreeData {
            digest: Digest::<33>::try_from(initial_digest).unwrap(),
            tree_flags: AvlTreeFlags::new(true, false, false),
            key_length: KEY_LENGTH as u32,
            value_length_opt: Some(Box::new(VALUE_LENGTH as u32)),
        };
        let avl_const = Constant::from(avl_tree_data);

        // Script: https://wallet.plutomonkey.com/p2s/?source=eyAvLyA9PT09PSBDb250cmFjdCBJbmZvcm1hdGlvbiA9PT09PSAvLwogIC8vIE5hbWU6IFZlcmlmeSBBVkwgdHJlZSB0ZXN0CiAgLy8KICAvLyBDb250ZXh0RXh0ZW5zaW9uIGNvbnN0YW50czoKICAvLyAwOiBBdmxUcmVlIC0gaW5pdGlhbCBzdGF0ZSBvZiB0aGUgQVZMIHRyZWUKICAvLyAxOiBDb2xsW0NvbGxbKEludCwgQ29sbFtCeXRlXSldXSAtIGluc2VydCBvcGVyYXRpb25zIGZvciBBVkwgdHJlZQogIC8vIDI6IENvbGxbQnl0ZV0gLSBBVkwgdHJlZSBwcm9vZgogIC8vIDM6IENvbGxbQnl0ZV0gLSBFeHBlY3RlZCBkaWdlc3QgYWZ0ZXIgaW5zZXJ0IG9wZXJhdGlvbnMgaGF2ZSBiZWVuIHBlcmZvcm1lZAogCgogIHZhbCB0cmVlICAgICAgICA9IGdldFZhcltBdmxUcmVlXSgwKS5nZXQKICB2YWwgb3BlcmF0aW9ucyAgPSBnZXRWYXJbQ29sbFsoQ29sbFtCeXRlXSwgQ29sbFtCeXRlXSldXSgxKS5nZXQKICB2YWwgcHJvb2YgICAgICAgPSBnZXRWYXJbQ29sbFtCeXRlXV0oMikuZ2V0CiAgdmFsIGRpZ2VzdCAgICAgID0gZ2V0VmFyW0NvbGxbQnl0ZV1dKDMpLmdldAoKICB2YWwgZW5kVHJlZSA9IHRyZWUuaW5zZXJ0KG9wZXJhdGlvbnMsIHByb29mKS5nZXQKICAKICBzaWdtYVByb3AgKGVuZFRyZWUuZGlnZXN0ID09IGRpZ2VzdCkKfQ==
        const SCRIPT_BYTES: &str = "2MEDDujrWqP7AmJZKvCPfe9bzoWQgmaLB9ykrQ9rvtEoKBpTd";
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::empty(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let mut constants = IndexMap::new();
        constants.insert(0_u8, avl_const);
        constants.insert(1_u8, operations_const);
        constants.insert(2_u8, proof);
        constants.insert(3_u8, Constant::from(resulting_digest));

        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values: constants });
        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(vec![unsigned_input]).unwrap(), None, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], vec![]).unwrap();
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature() {
        // (old) Script: https://wallet.plutomonkey.com/p2s/?source=ewogIAogIHZhbCBnZW5lcmF0b3IgPSBJTlBVVFMoMCkuUjRbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgcHViS2V5ID0gSU5QVVRTKDApLlI1W0dyb3VwRWxlbWVudF0uZ2V0CiAgdmFsIGNoYWxsZW5nZSA9IElOUFVUUygwKS5SNltCaWdJbnRdLmdldAogIHZhbCByZXNwb25zZSA9IElOUFVUUygwKS5SN1tCaWdJbnRdLmdldAogIHZhbCBtZXNzYWdlID0gSU5QVVRTKDApLlI4W0NvbGxbQnl0ZV1dLmdldAogIAogIGRlZiBnZXRGaWF0U2hhbWlyQ2hhbGxlbmdlKGUgOiAoR3JvdXBFbGVtZW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkpOiBCaWdJbnQgPSB7CiAgICB2YWwgcGsgPSBlLl8xCiAgICB2YWwgY29tbWl0bWVudCA9IGUuXzIuXzEKICAgIHZhbCBtc2cgPSBlLl8yLl8yCiAgICBieXRlQXJyYXlUb0JpZ0ludChibGFrZTJiMjU2KHBrLmdldEVuY29kZWQgKysgY29tbWl0bWVudC5nZXRFbmNvZGVkICsrIG1zZykpCiAgfQogIAogIGRlZiB2ZXJpZnlTY2hub3JyKGU6IChHcm91cEVsZW1lbnQsIChCaWdJbnQsIChCaWdJbnQsIENvbGxbQnl0ZV0pKSkpOiBCb29sZWFuID0gewogICAgdmFsIHBrICAgICAgICAgPSBlLl8xCiAgICB2YWwgY2hhbGxlbmdlXyA9IGUuXzIuXzEKICAgIHZhbCByZXNwb25zZV8gID0gZS5fMi5fMi5fMQogICAgdmFsIG1zZyAgICAgICAgPSBlLl8yLl8yLl8yCiAgICB2YWwgciAgICAgICAgICA9IGdlbmVyYXRvci5leHAocmVzcG9uc2VfKS5tdWx0aXBseShwdWJLZXkuZXhwKC1jaGFsbGVuZ2VfKSkKICAgIGNoYWxsZW5nZSA9PSBnZXRGaWF0U2hhbWlyQ2hhbGxlbmdlKChwaywgKHIsIG1zZykpKSAKICB9CiAgc2lnbWFQcm9wICh2ZXJpZnlTY2hub3JyKChwdWJLZXksIChjaGFsbGVuZ2UsIChyZXNwb25zZSwgbWVzc2FnZSkpKSkpCn0=
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBwdWJLZXkgPSBJTlBVVFMoMCkuUjRbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgY2hhbGxlbmdlID0gSU5QVVRTKDApLlI1W0JpZ0ludF0uZ2V0CiAgdmFsIHJlc3BvbnNlID0gSU5QVVRTKDApLlI2W0dyb3VwRWxlbWVudF0uZ2V0CiAgdmFsIG1lc3NhZ2UgPSBJTlBVVFMoMCkuUjdbQ29sbFtCeXRlXV0uZ2V0CiAgCiAgZGVmIGdldEZpYXRTaGFtaXJDaGFsbGVuZ2UoZSA6IChHcm91cEVsZW1lbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSk6IEJpZ0ludCA9IHsKICAgIHZhbCBwayA9IGUuXzEKICAgIHZhbCBjb21taXRtZW50ID0gZS5fMi5fMQogICAgdmFsIG1zZyA9IGUuXzIuXzIKICAgIGJ5dGVBcnJheVRvQmlnSW50KGJsYWtlMmIyNTYocGsuZ2V0RW5jb2RlZCArKyBjb21taXRtZW50LmdldEVuY29kZWQgKysgbXNnKSkKICB9CiAgCiAgZGVmIHZlcmlmeVNjaG5vcnIoZTogKEdyb3VwRWxlbWVudCwgKEJpZ0ludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpKSk6IEJvb2xlYW4gPSB7CiAgICB2YWwgcGsgICAgICAgICA9IGUuXzEKICAgIHZhbCBjaGFsbGVuZ2VfID0gZS5fMi5fMQogICAgdmFsIHJlc3BvbnNlXyAgPSBlLl8yLl8yLl8xCiAgICB2YWwgbXNnICAgICAgICA9IGUuXzIuXzIuXzIKICAgIHZhbCByICAgICAgICAgID0gcmVzcG9uc2VfLm11bHRpcGx5KHB1YktleS5leHAoLWNoYWxsZW5nZV8pKQogICAgY2hhbGxlbmdlID09IGdldEZpYXRTaGFtaXJDaGFsbGVuZ2UoKHBrLCAociwgbXNnKSkpIAogIH0KICBzaWdtYVByb3AgKHZlcmlmeVNjaG5vcnIoKHB1YktleSwgKGNoYWxsZW5nZSwgKHJlc3BvbnNlLCBtZXNzYWdlKSkpKSkKfQ==
        const SCRIPT_BYTES: &str = "8D7RfbcK86uwBfxDS37iPYDToACJZYTGntpXT1wjaA3duKvKQHzanqLwTXoM9xoDEAwWbPJHj6MvJUSQj38sng6zjoVv9bpJ4avT293J5KSDUWuGPZ1Zgu28wuS8STm1zVjiT9vKRNyjTvGHutoAPZ9yXpK7fECfMzuiHWkugUBKC6kznT1W4t56sYNBibNPSmz55dy7ubiDd4eSexGBz3HtGDqqvoxEVt49ExMrRF5MhJxk4KyFBKZRXs6ZMhvP4xuJvnNCURFyPipc1s2bB1hcRXgCaG1yreaJZaaz5tiVkCndPAKmmrA6i9VR6TGVJL3Ms72KHwRCBzTizU81FeZDzD9KM7jij1KG7FifAaCQkXVTQ45MLuabJbrFbrnKxKu7SCqeCfgxUmDymEAum4MAJmKQMRWzdtJg3HcnZxJRt5VqsQqMWr2GKnrqFmXBDbMYWE96PTbihqocmRyHs8rRDsy6X6gEZzd9PboPfbyDoiBmvPkxDdbSDfQWk2hhBu7x1AR23WLZWauReAX5qdoa34a8dnMH2agi5A6jMVjtHgJd3afmdpKnEhk1E";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let msg = b"foo".as_slice();
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let pk = secret_key.public_key().to_projective();
        let signature_bytes = SigningKey::from(secret_key).sign(msg).to_bytes();

        let (r_bytes, s_bytes) = signature_bytes.split_at(32);
        let r: FieldElement = Option::from(FieldElement::from_bytes(r_bytes.into())).unwrap();

        // This is wrong. I think we need: https://github.com/RustCrypto/elliptic-curves/blob/c74d363a7c60acf6f34cc8b25ca9acb9b26e8b7d/k256/src/schnorr/verifying.rs#L78
        let r_point: k256::ProjectivePoint = r.map_to_curve();

        let s = NonZeroScalar::try_from(s_bytes).unwrap();
        let s_biguint = scalar_to_biguint(*s.as_ref());
        println!("# bytes: {}", s_biguint.to_bytes_be().len());
        let upper = BigUint::from_bytes_be(&s_biguint.to_bytes_be()[..16]);
        let upper_256 = BigInt256::try_from(upper).unwrap();
        assert_eq!(upper_256.sign(), Sign::Plus);
        let lower = BigUint::from_bytes_be(&s_biguint.to_bytes_be()[16..]);
        let lower_256 = BigInt256::try_from(lower).unwrap();
        assert_eq!(lower_256.sign(), Sign::Plus);

        let mut s_bytes = upper_256.to_signed_bytes_be();
        // Need this variable because we could add an extra byte to the encoding for signed-representation.
        let first_len = s_bytes.len() as i32;
        s_bytes.extend(lower_256.to_signed_bytes_be());

        println!("first_len: {}, S_BYTES_LEN: {}", first_len, s_bytes.len());
        let pp = BigInt256::from_str_radix("340282366920938463463374607431768211456", 10).unwrap();

        let mut registers = HashMap::new();

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(EcPoint::from(pk)));
        registers.insert(NonMandatoryRegisterId::R5, (first_len, s_bytes).into());
        registers.insert(NonMandatoryRegisterId::R6, Constant::from(EcPoint::from(r_point)));
        registers.insert(NonMandatoryRegisterId::R7, Constant::from(msg.to_vec()));
        registers.insert(NonMandatoryRegisterId::R8, Constant::from(generator()));
        registers.insert(NonMandatoryRegisterId::R9, Constant::from(pp));

        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::new(registers).unwrap(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension::empty());
        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(vec![unsigned_input]).unwrap(), None, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], vec![]).unwrap();
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_bigint() {
        let sss = BigInt::from(2).pow(255) - BigInt::from(1);
        println!("{}", sss);
        let max_val = Int256::max_value();
        let z = BigInt::parse_bytes(
            b"115404002681060032338124913795188400094157460408070686874335705470421013420426",
            10,
        )
        .unwrap();
        println!("____ {}", max_val.0 - z);
        //println!("{}", *max_val);
        //let bi = BigInt::parse_bytes(b"107886196495854963326286130888784860201721730589241313441441967201926281169315", 10).unwrap();
        //let bi = BigInt256::try_from(bi).unwrap();
        //println!("{}", bi);
    }

    fn get_wallet() -> Wallet {
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed")
    }

    fn scalar_to_biguint(scalar: Scalar) -> BigUint {
        scalar
            .to_bytes()
            .iter()
            .enumerate()
            .map(|(i, w)| w.to_biguint().unwrap() << ((31 - i) * 8))
            .sum()
    }

    fn dummy_ergo_state_context() -> ErgoStateContext {
        let mut rng = OsRng;
        let pre_header = PreHeader {
            version: 1,
            parent_id: BlockId(Digest::zero()),
            timestamp: 1234,
            n_bits: 1234,
            height: 900000,
            miner_pk: Box::new(EcPoint::from(
                SecretKey::random(&mut rng).public_key().to_projective(),
            )),
            votes: Votes([0, 0, 0]),
        };

        let header = Header {
            version: 1,
            id: BlockId(Digest::zero()),
            parent_id: BlockId(Digest::zero()),
            ad_proofs_root: Digest::zero(),
            state_root: Digest::zero(),
            transaction_root: Digest::zero(),
            timestamp: 1234,
            n_bits: 1234,
            height: 900000,
            extension_root: Digest::zero(),
            autolykos_solution: ergo_lib::ergo_chain_types::AutolykosSolution {
                miner_pk: Box::new(EcPoint::from(
                    SecretKey::random(&mut rng).public_key().to_projective(),
                )),
                pow_onetime_pk: None,
                nonce: vec![0, 1, 2, 3],
                pow_distance: None,
            },
            votes: Votes([0, 0, 0]),
        };
        let headers = [
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
        ];
        ErgoStateContext { pre_header, headers }
    }
}
