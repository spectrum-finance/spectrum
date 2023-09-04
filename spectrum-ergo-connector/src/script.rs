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
    use elliptic_curve::ops::LinearCombination;
    use elliptic_curve::ops::Reduce;
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
    use k256::U256;
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
    use sha2::Digest as OtherDigest;
    use sha2::Sha256;
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
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBwdWJLZXkgICAgICAgICA9IElOUFVUUygwKS5SNFtHcm91cEVsZW1lbnRdLmdldAogIHZhbCBjaGFsbGVuZ2UgICAgICA9IElOUFVUUygwKS5SNVsoSW50LCBDb2xsW0J5dGVdKV0uZ2V0CiAgdmFsIHJlc3BvbnNlICAgICAgID0gSU5QVVRTKDApLlI2W0dyb3VwRWxlbWVudF0uZ2V0IC8vIFIgaW4gQklQLTAzNDAKICB2YWwgbWVzc2FnZSAgICAgICAgPSBJTlBVVFMoMCkuUjdbQ29sbFtCeXRlXV0uZ2V0CiAgdmFsIGdyb3VwR2VuZXJhdG9yID0gSU5QVVRTKDApLlI4W0dyb3VwRWxlbWVudF0uZ2V0CiAgdmFsIHAxT3ZlcjIgICAgICAgID0gSU5QVVRTKDApLlI5W0JpZ0ludF0uZ2V0CgogIHZhbCByciAgICAgICAgPSBnZXRWYXJbQ29sbFtCeXRlXV0oMCkuZ2V0CiAgdmFsIHJpZ2h0ICAgICA9IGdldFZhcltHcm91cEVsZW1lbnRdKDEpLmdldAogIHZhbCBwa0J5dGVzICAgPSBnZXRWYXJbQ29sbFtCeXRlXV0oMikuZ2V0IC8vIGVuY29kZWQgeC1jb29yZGluYXRlIG9mIFAKCiAgZGVmIG15RXhwKGU6IChHcm91cEVsZW1lbnQsIChDb2xsW0J5dGVdLCBJbnQpKSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICB2YWwgeCA9IGUuXzEKICAgIHZhbCB5ID0gZS5fMi5fMQogICAgdmFsIGxlbiA9IGUuXzIuXzIKICAgIHZhbCB1cHBlciA9IGJ5dGVBcnJheVRvQmlnSW50KHkuc2xpY2UoMCwgbGVuKSkKICAgIHZhbCBsb3dlciA9IGJ5dGVBcnJheVRvQmlnSW50KHkuc2xpY2UobGVuLCB5LnNpemUpKQogICAKICAgIHguZXhwKHVwcGVyKS5leHAocDFPdmVyMikubXVsdGlwbHkoeC5leHAobG93ZXIpKQogIH0KCiAgZGVmIHRvU2lnbmVkQnl0ZXMoYjogQ29sbFtCeXRlXSkgOiBDb2xsW0J5dGVdID0gewogICAgaWYgKGIoMCkgPCAwICkgeyAvLyYmICEoYigwKSA9PSAxMjggJiYgYi5zbGljZSgxLGIuc2l6ZSkuZm9yYWxsIHsoYjogQnl0ZSkgPT4gYiA9PSAwfSkpIHsKICAgICAgICBDb2xsKDAudG9CeXRlKS5hcHBlbmQoYikKICAgIH0gZWxzZSB7CiAgICAgICAgYgogICAgfQogIH0KCiAgZGVmIGdldEZpYXRTaGFtaXJDaGFsbGVuZ2UoZSA6IChHcm91cEVsZW1lbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSk6IChJbnQsIENvbGxbQnl0ZV0pID0gewogICAgdmFsIHBrID0gZS5fMQogICAgdmFsIGNvbW1pdG1lbnQgPSBlLl8yLl8xCiAgICB2YWwgbXNnID0gZS5fMi5fMgogCiAgICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgICB2YWwgY2hhbGxlbmdlVGFnID0gc2hhMjU2KENvbGwoNjYsIDczLCA4MCwgNDgsIDUxLCA1MiwgNDgsIDQ3LCA5OSwgMTA0LCA5NywgMTA4LCAxMDgsIDEwMSwgMTEwLCAxMDMsIDEwMSkubWFwIHsgKHg6SW50KSA9PiB4LnRvQnl0ZSB9KQogICAgdmFsIHJhdyA9IHNoYTI1NihjaGFsbGVuZ2VUYWcgKysgY2hhbGxlbmdlVGFnICsrIHJyICsrIHBrQnl0ZXMgKysgbXNnKQogICAgdmFsIGZpcnN0ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwxNikpCiAgICAoZmlyc3Quc2l6ZSwgZmlyc3QuYXBwZW5kKHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDE2LHJhdy5zaXplKSkpKQogICAgCiAgfQogIAogIGRlZiB2ZXJpZnlTY2hub3JyKGU6IChHcm91cEVsZW1lbnQsIChDb2xsW0J5dGVdLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkpKTogQm9vbGVhbiA9IHsKICAgIHZhbCBwayAgICAgICAgID0gZS5fMQogICAgdmFsIHMgICAgICAgICAgPSBlLl8yLl8xCiAgICB2YWwgciAgICAgICAgICA9IGUuXzIuXzIuXzEKICAgIHZhbCBtc2cgICAgICAgID0gZS5fMi5fMi5fMgogICAgdmFsIGNoYWxsICA9IGdldEZpYXRTaGFtaXJDaGFsbGVuZ2UoKHBrLCAociwgbXNnKSkpCgogICAgbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCAocywgY2hhbGxlbmdlLl8xKSkpID09ICBteUV4cCgocGssIChjaGFsbC5fMiwgY2hhbGwuXzEpKSkubXVsdGlwbHkocikKICB9CgogIHNpZ21hUHJvcCAodmVyaWZ5U2Nobm9ycigocHViS2V5LCAoY2hhbGxlbmdlLl8yLCAocmVzcG9uc2UsIG1lc3NhZ2UpKSkpKQp9
        const SCRIPT_BYTES: &str = "W56sEkkPGgLFS4QvRKj2uLg28yQPWP5x7oG6pJtwPApV9yGiN9yEpYFEvnZCELrMvNNjGQE9qm5HBiJ3FgTMC7Tw9p1D3bp32RRu6HpzGJ7bxHyyMKhhY8N7Wo6ZNTSnohxX1ghiTjh3y4moBmzHjE5scRACJG1mjEKDmegbHMeryFyzkAA8GCqT1M2nzgbebrVqLPFsSMqy34u3i9D4WRxUpZdczHuNhqq4KSzHKoXKCTVFHJfLy2AsygzXs83fJ1wjKjtDCZC84yGVivd2u8fzE6dqEdmQqo1hivSibywZyLUqqAyS2eV5wp3d8AgBoDSCAoEEYW9qXk5LBU7hQcQm7qj8rUywMm58pve3hdctPNzp6GrxYJhYDVyfQr4Sg7kM9ZgZ4MwvEwAg126bkWt43QgpgGGb7SGDznTsFFDh3ovEBugLx2S6fUa2vE9Zc7QpavqjTztJDfLLuhZvHSDxKj6xsRWCRosidHxb53DcpEKCGFFuZPuRAAQN7iaj5ur9tS1Xa4r1cQ5PwBCxJj7Giwqm8E8Ct6EnNPKa95R1wdD";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let msg = b"foo".as_slice();
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let pk = secret_key.public_key().to_projective();
        let signing_key = SigningKey::from(secret_key);
        let signature = signing_key.sign(msg);
        let signature_bytes = signature.to_bytes();

        let (r_bytes, s_bytes) = signature_bytes.split_at(32);
        let r: FieldElement = Option::from(FieldElement::from_bytes(r_bytes.into())).unwrap();

        const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(signing_key.verifying_key().to_bytes())
                .chain_update(msg)
                .finalize(),
        );
        let s = NonZeroScalar::try_from(s_bytes).unwrap();
        let r_point = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &s,
            &ProjectivePoint::from(signing_key.verifying_key().as_affine()),
            &-e,
        );

        let right = r_point + ProjectivePoint::from(signing_key.verifying_key().as_affine()) * e;

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

        registers.insert(
            NonMandatoryRegisterId::R4,
            Constant::from(EcPoint::from(ProjectivePoint::from(
                signing_key.verifying_key().as_affine(),
            ))),
        );
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

        let mut constants = IndexMap::new();
        constants.insert(0_u8, Constant::from(r.to_bytes().to_vec()));
        constants.insert(1_u8, Constant::from(EcPoint::from(right)));
        constants.insert(
            2_u8,
            Constant::from(signing_key.verifying_key().to_bytes().to_vec()),
        );

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values: constants });
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

    fn tagged_hash(tag: &[u8]) -> Sha256 {
        let tag_hash = Sha256::digest(tag);
        let mut digest = Sha256::new();
        digest.update(tag_hash);
        digest.update(tag_hash);
        digest
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
