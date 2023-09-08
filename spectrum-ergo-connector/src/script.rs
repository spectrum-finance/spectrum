use ergo_lib::ergotree_ir::types::{
    stuple::{STuple, TupleItems},
    stype::SType,
};
use scorex_crypto_avltree::{
    batch_node::{Node, NodeHeader},
    operation::Digest32,
};

fn dummy_resolver(digest: &Digest32) -> Node {
    Node::LabelOnly(NodeHeader::new(Some(digest.clone()), None))
}

fn schnorr_signature_verification_ergoscript_type() -> SType {
    //   ( ( Int, (GroupElement, Coll[Byte]) ),
    //     ( (Coll[Byte], Int), (GroupElement, Coll[Byte]) )
    //   )

    let bytes_type = SType::SColl(Box::new(SType::SByte));
    let group_element_and_bytes = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![SType::SGroupElement, bytes_type.clone()]).unwrap(),
    });

    // ( Int, (GroupElement, Coll[Byte]) )
    let left = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![SType::SInt, group_element_and_bytes.clone()]).unwrap(),
    });

    let right = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![
            SType::STuple(STuple {
                items: TupleItems::from_vec(vec![bytes_type, SType::SInt]).unwrap(),
            }),
            group_element_and_bytes,
        ])
        .unwrap(),
    });

    SType::STuple(STuple {
        items: TupleItems::from_vec(vec![left, right]).unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use blake2::Blake2b;
    use bytes::Bytes;
    use elliptic_curve::consts::U32;
    use elliptic_curve::ops::LinearCombination;
    use elliptic_curve::ops::Reduce;
    use ergo_lib::chain::ergo_state_context::ErgoStateContext;
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
    use ergo_lib::ergotree_ir::types::stuple::STuple;
    use ergo_lib::ergotree_ir::types::stuple::TupleItems;
    use ergo_lib::ergotree_ir::types::stype::SType;
    use ergo_lib::wallet::miner_fee::MINERS_FEE_ADDRESS;
    use ergo_lib::wallet::tx_context::TransactionContext;
    use ergo_lib::wallet::Wallet;
    use indexmap::IndexMap;
    use k256::schnorr::signature::Signer;
    use k256::schnorr::Signature;
    use k256::schnorr::SigningKey;
    use k256::FieldElement;
    use k256::NonZeroScalar;
    use k256::ProjectivePoint;
    use k256::Scalar;
    use k256::SecretKey;
    use k256::U256;
    use num_bigint::BigUint;
    use num_bigint::Sign;
    use num_bigint::ToBigUint;
    use num_traits::Num;
    use rand::rngs::OsRng;
    use rand::Rng;
    use scorex_crypto_avltree::authenticated_tree_ops::*;
    use scorex_crypto_avltree::batch_avl_prover::BatchAVLProver;
    use scorex_crypto_avltree::batch_node::*;
    use scorex_crypto_avltree::operation::*;
    use sha2::Digest as OtherDigest;
    use sha2::Sha256;
    use spectrum_crypto::digest::blake2b256_hash;
    use spectrum_crypto::digest::Blake2bDigest256;
    use spectrum_crypto::pubkey::PublicKey;
    use spectrum_handel::Threshold;
    use spectrum_sigma::crypto::aggregate_commitment;
    use spectrum_sigma::crypto::aggregate_pk;
    use spectrum_sigma::crypto::aggregate_response;
    use spectrum_sigma::crypto::challenge;
    use spectrum_sigma::crypto::exclusion_proof;
    use spectrum_sigma::crypto::individual_input;
    use spectrum_sigma::crypto::response;
    use spectrum_sigma::crypto::schnorr_commitment_pair;
    use spectrum_sigma::crypto::verify;
    use spectrum_sigma::crypto::verify_response;
    use spectrum_sigma::AggregateCommitment;
    use spectrum_sigma::Commitment;
    use std::collections::HashMap;

    use crate::script::schnorr_signature_verification_ergoscript_type;

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
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature() {
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBtZXNzYWdlICAgICAgICA9IElOUFVUUygwKS5SNFtDb2xsW0J5dGVdXS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgPSBJTlBVVFMoMCkuUjVbR3JvdXBFbGVtZW50XS5nZXQKCiAgdmFsIHZlcmlmaWNhdGlvbkRhdGEgPSBnZXRWYXJbQ29sbFsoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSApXV0oMCkuZ2V0CiAKICAvLyBQZXJmb3JtcyBleHBvbmVudGlhdGlvbiBvZiBhIEdyb3VwRWxlbWVudCBieSBhbiB1bnNpZ25lZCAyNTZiaXQKICAvLyBpbnRlZ2VyIEkgdXNpbmcgdGhlIGZvbGxvd2luZyBkZWNvbXBvc2l0aW9uIG9mIEk6CiAgLy8gTGV0IGUgPSAoZywgKGIsIG4pKS4gVGhlbiB0aGlzIGZ1bmN0aW9uIGNvbXB1dGVzOgogIC8vCiAgLy8gICBnXkkgPT0gKGdeYigwLG4pKV5wICogZ14oYihuLi4pKQogIC8vIHdoZXJlCiAgLy8gIC0gYigwLG4pIGlzIHRoZSBmaXJzdCBuIGJ5dGVzIG9mIGEgcG9zaXRpdmUgQmlnSW50IGBVYAogIC8vICAtIGIobi4uKSBhcmUgdGhlIHJlbWFpbmluZyBieXRlcyBzdGFydGluZyBmcm9tIGluZGV4IG4uIFRoZXNlIGJ5dGVzCiAgLy8gICAgYWxzbyByZXByZXNlbnQgYSBwb3NpdGl2ZSBCaWdJbnQgYExgLgogIC8vICAtIHAgaXMgMzQwMjgyMzY2OTIwOTM4NDYzNDYzMzc0NjA3NDMxNzY4MjExNDU2IGJhc2UgMTAuCiAgLy8gIC0gSSA9PSBVICogcCArIEwKICBkZWYgbXlFeHAoZTogKEdyb3VwRWxlbWVudCwgKENvbGxbQnl0ZV0sIEludCkpKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCB4ID0gZS5fMQogICAgdmFsIHkgPSBlLl8yLl8xCiAgICB2YWwgbGVuID0gZS5fMi5fMgogICAgdmFsIHVwcGVyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZSgwLCBsZW4pKQogICAgdmFsIGxvd2VyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZShsZW4sIHkuc2l6ZSkpCgogICAgLy8gVGhlIGZvbGxvd2luZyB2YWx1ZSBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZS0xMC4KICAgIHZhbCBwID0gYnl0ZUFycmF5VG9CaWdJbnQoZnJvbUJhc2U2NCgiQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKSkKICAgCiAgICB4LmV4cCh1cHBlcikuZXhwKHApLm11bHRpcGx5KHguZXhwKGxvd2VyKSkKICB9CgogIC8vIENvbnZlcnRzIGEgYmlnLWVuZGlhbiBieXRlIHJlcHJlc2VudGF0aW9uIG9mIGFuIHVuc2lnbmVkIGludGVnZXIgaW50byBpdHMKICAvLyBlcXVpdmFsZW50IHNpZ25lZCByZXByZXNlbnRhdGlvbgogIGRlZiB0b1NpZ25lZEJ5dGVzKGI6IENvbGxbQnl0ZV0pIDogQ29sbFtCeXRlXSA9IHsKICAgIC8vIE5vdGUgdGhhdCBhbGwgaW50ZWdlcnMgKGluY2x1ZGluZyBCeXRlKSBpbiBFcmdvc2NyaXB0IGFyZSBzaWduZWQuIEluIHN1Y2gKICAgIC8vIGEgcmVwcmVzZW50YXRpb24sIHRoZSBtb3N0LXNpZ25pZmljYW50IGJpdCAoTVNCKSBpcyB1c2VkIHRvIHJlcHJlc2VudCB0aGUKICAgIC8vIHNpZ247IDAgZm9yIGEgcG9zaXRpdmUgaW50ZWdlciBhbmQgMSBmb3IgbmVnYXRpdmUuIE5vdyBzaW5jZSBgYmAgaXMgYmlnLQogICAgLy8gZW5kaWFuLCB0aGUgTVNCIHJlc2lkZXMgaW4gdGhlIGZpcnN0IGJ5dGUgYW5kIE1TQiA9PSAxIGluZGljYXRlcyB0aGF0IGV2ZXJ5CiAgICAvLyBiaXQgaXMgdXNlZCB0byBzcGVjaWZ5IHRoZSBtYWduaXR1ZGUgb2YgdGhlIGludGVnZXIuIFRoaXMgbWVhbnMgdGhhdCBhbgogICAgLy8gZXh0cmEgMC1iaXQgbXVzdCBiZSBwcmVwZW5kZWQgdG8gYGJgIHRvIHJlbmRlciBpdCBhIHZhbGlkIHBvc2l0aXZlIHNpZ25lZAogICAgLy8gaW50ZWdlci4KICAgIC8vCiAgICAvLyBOb3cgc2lnbmVkIGludGVnZXJzIGFyZSBuZWdhdGl2ZSBpZmYgTVNCID09IDEsIGhlbmNlIHRoZSBjb25kaXRpb24gYmVsb3cuCiAgICBpZiAoYigwKSA8IDAgKSB7CiAgICAgICAgQ29sbCgwLnRvQnl0ZSkuYXBwZW5kKGIpCiAgICB9IGVsc2UgewogICAgICAgIGIKICAgIH0KICB9CiAgICAKICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgdmFsIGNoYWxsZW5nZVRhZyA9IHNoYTI1NihDb2xsKDY2LCA3MywgODAsIDQ4LCA1MSwgNTIsIDQ4LCA0NywgOTksIDEwNCwgOTcsIDEwOCwgMTA4LCAxMDEsIDExMCwgMTAzLCAxMDEpLm1hcCB7ICh4OkludCkgPT4geC50b0J5dGUgfSkKCgogIHNpZ21hUHJvcCAoCiAgICB2ZXJpZmljYXRpb25EYXRhLmZvcmFsbCB7IChlOiAoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSkpID0+CiAgICAgIHZhbCBwdWJLZXlUdXBsZSA9IGUuXzEuXzIKICAgICAgdmFsIHMgID0gZS5fMi5fMQogICAgICB2YWwgcmVzcG9uc2VUdXBsZSA9IGUuXzIuXzIKCiAgICAgIHZhbCBwdWJLZXkgICAgICAgICA9IHB1YktleVR1cGxlLl8xIC8vIFAKICAgICAgdmFsIHBrQnl0ZXMgICAgICAgID0gcHViS2V5VHVwbGUuXzIgLy8gZW5jb2RlZCB4LWNvb3JkaW5hdGUgb2YgUAogICAgICB2YWwgcmVzcG9uc2UgICAgICAgPSByZXNwb25zZVR1cGxlLl8xIC8vIFIgaW4gQklQLTAzNDAKICAgICAgdmFsIHJCeXRlcyAgICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMiAvLyBCeXRlIHJlcHJlc2VudGF0aW9uIG9mICdyJwoKCiAgICAgIHZhbCByYXcgPSBzaGEyNTYoY2hhbGxlbmdlVGFnICsrIGNoYWxsZW5nZVRhZyArKyByQnl0ZXMgKysgcGtCeXRlcyArKyBtZXNzYWdlKQogCiAgICAgIC8vIE5vdGUgdGhhdCB0aGUgb3V0cHV0IG9mIFNIQTI1NiBpcyBhIGNvbGxlY3Rpb24gb2YgYnl0ZXMgdGhhdCByZXByZXNlbnRzIGFuIHVuc2lnbmVkIDI1NmJpdCBpbnRlZ2VyLiAKICAgICAgdmFsIGZpcnN0ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwxNikpCiAgICAgIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZSgxNixyYXcuc2l6ZSkpKQogICAgICB2YWwgZmlyc3RJbnROdW1CeXRlcyA9IGZpcnN0LnNpemUKICAgICAgbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCBzKSkgPT0gIG15RXhwKChwdWJLZXksIChjb25jYXRCeXRlcywgZmlyc3RJbnROdW1CeXRlcykpKS5tdWx0aXBseShyZXNwb25zZSkKICAgIH0KICAgICAgCiAgKQp9
        const SCRIPT_BYTES: &str = "291X3UroKTCRC8KCGxEMLgq35xFL9Hng8iuN1CWPjV8cYBzBr49FQ6KYioEMd6nfB7Vw7rt2m3pfU7sgCbzKv67pFj5iRVgxGvp5XzYSR43GJEjqkNL8HGoU7EDyqTDir9Bj6UJMKyACzzBr4ui7dqkKAwTrY4rYsvvgUp1GZYEKun6ZqSCYSRTyd4PztGUXVGmWykSajpjB9ddp5kwn15qNYT9HJ9rpENofSaeoroooLaAs3d9Z1idarto3zY2YnHN31fa67L3xDtRsCZ2wC3yp2RV9VroiWggAD98ddViYuHXD6eFhu9ifFuRPbR1k96CMo9U2Mup9kiJUcx6TPhKPBn8gWqqRemGAs4EVuz75d52wgqfQxgc6hEDQwUh7BedjusfXeSTneVCcZevRJFmgFnpo2dnNk5PotVXQGqHSJBbe48mU4S7eZ6px5ZtyjPsAdjMffHX3p33f9eCdJkzkQYhRDEzRYM29faVRemnDz3PfgrSUiMioFc68K54B";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let msg = b"foo".as_slice();
        let mut rng = OsRng;
        let mut sigs = vec![];

        for i in 0..100 {
            let secret_key = SecretKey::random(&mut rng);
            let signing_key = SigningKey::from(secret_key);
            let signature = signing_key.sign(msg);
            sigs.push((
                i as usize,
                Some((Commitment::from(*signing_key.verifying_key()), signature)),
            ));
        }

        let schnorr_sig_data = serialize_exclusion_set(sigs, msg);

        let mut registers = HashMap::new();

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(msg.to_vec()));
        registers.insert(NonMandatoryRegisterId::R5, Constant::from(generator()));
        let mut values = IndexMap::new();
        values.insert(0, schnorr_sig_data);
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
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });
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

    fn serialize_exclusion_set(
        exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
        md: &[u8],
    ) -> Constant {
        let mut elem_tpe = None;
        let mut items = vec![];
        let filtered_exclusion_set = exclusion_set.into_iter().filter_map(|(ix, pair)| {
            if let Some((Commitment(verifying_key), sig)) = pair {
                Some((ix, verifying_key, sig))
            } else {
                None
            }
        });
        for (ix, verifying_key, signature) in filtered_exclusion_set {
            let signature_bytes = signature.to_bytes();

            // The components (r,s) of the taproot `Signature` struct are not public, but we can
            // extract it through its byte representation.
            let (r_bytes, s_bytes) = signature_bytes.split_at(32);
            let r: FieldElement = Option::from(FieldElement::from_bytes(r_bytes.into())).unwrap();

            const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
            //  int(sha256(sha256(CHALLENGE_TAG) || sha256(CHALLENGE_TAG) || bytes(r) || bytes(P) || m)) mod n
            let e = <Scalar as Reduce<U256>>::reduce_bytes(
                &tagged_hash(CHALLENGE_TAG)
                    .chain_update(r.to_bytes())
                    .chain_update(verifying_key.to_bytes())
                    .chain_update(md)
                    .finalize(),
            );
            let s = NonZeroScalar::try_from(s_bytes).unwrap();

            // R
            let r_point = ProjectivePoint::lincomb(
                &ProjectivePoint::GENERATOR,
                &s,
                &ProjectivePoint::from(verifying_key.as_affine()),
                &-e,
            );

            // The taproot signature satisfies:
            //     g ^ s == R * P^e
            // Note: `k256` uses additive notation for elliptic-curves, so we can compute the right
            // hand side with:
            //   r_point + ProjectivePoint::from(verifying_key.as_affine()) * e;
            //
            // Note in the above equation that the values `s` and `e` have a 256bit UNSIGNED integer
            // representation. This is a problem for Ergoscript since the largest integer values it
            // allows for is 256bit signed. We can work around the problem by splitting the value
            // into 2 signed ints.
            //
            // Let `B` denote the big-endian unsigned byte representation of `s`. Let `U` and `L`
            // denote the first 16 and last 16 bytes of `B`, respectively. Then `U` and `L` are
            // themselves unsigned integers. Moreover,
            //    B == U*p + L, where p == 340282366920938463463374607431768211456
            //
            // We want to use this decomposition on the ergo side, but we need to convert `U` and `L`
            // into signed integers, `U_S` and `L_S`. We need to be careful as `U_S` and/or `L_S` could
            // each require 17 bytes if the most-significant-bit of `U`/`L` is 1 (and so we need to
            // prepend a zero byte to accomodate the sign-bit).
            //
            // So we can transport `s` across the boundary with the bytes of [U_S | L_S], and decoding
            // `U_S` and `L_S` within Ergoscript.
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
            let p = BigInt256::from_str_radix("340282366920938463463374607431768211456", 10).unwrap();

            println!(
                "PP_base64: {}",
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(p.to_signed_bytes_be())
            );

            // P from BIP-0340
            let pubkey_point = EcPoint::from(ProjectivePoint::from(verifying_key.as_affine()));
            // The x-coordinate of P
            let pubkey_x_coords = verifying_key.to_bytes().to_vec();

            let pubkey_tuple: Constant =
                (Constant::from(pubkey_point), Constant::from(pubkey_x_coords)).into();
            let with_ix: Constant = (Constant::from(ix as i32), pubkey_tuple).into();
            let s_tuple: Constant = (Constant::from(s_bytes), Constant::from(first_len)).into();
            let r_tuple: Constant = (
                Constant::from(EcPoint::from(r_point)),
                Constant::from(r.to_bytes().to_vec()),
            )
                .into();
            let s_r_tuple: Constant = (s_tuple, r_tuple).into();
            let elem: Constant = (with_ix, s_r_tuple).into();

            items.push(elem.v);

            if elem_tpe.is_none() {
                elem_tpe = Some(elem.tpe.clone());
            }
        }
        if let Some(elem_tpe) = elem_tpe {
            Constant {
                tpe: SType::SColl(Box::new(elem_tpe.clone())),
                v: Literal::Coll(CollKind::WrappedColl { elem_tpe, items }),
            }
        } else {
            let schnorr_sig_elem_type = schnorr_signature_verification_ergoscript_type();
            Constant {
                tpe: SType::SColl(Box::new(schnorr_sig_elem_type.clone())),
                v: Literal::Coll(CollKind::WrappedColl {
                    elem_tpe: schnorr_sig_elem_type,
                    items: vec![],
                }),
            }
        }
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

    #[test]
    fn verify_non_byzantine_ergoscript() {
        let num_participants = 16;
        let mut rng = OsRng;
        let md = blake2b256_hash(b"foo");
        let individual_keys = (0..num_participants)
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let (commitment_sk, commitment) = schnorr_commitment_pair();
                (sk, pk, commitment_sk, commitment)
            })
            .collect::<Vec<_>>();
        let committee = individual_keys
            .iter()
            .map(|(_, pk, _, _)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = individual_keys
            .iter()
            .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
            individual_inputs.clone(),
        );
        let aggregate_commitment = aggregate_commitment(
            individual_keys
                .iter()
                .map(|(_, _, _, commitment)| commitment.clone())
                .collect(),
        );
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let individual_responses = individual_keys
            .iter()
            .enumerate()
            .map(|(i, (sk, pk, commitment_sk, _))| {
                response(commitment_sk.clone(), sk.clone(), challenge, individual_inputs[i])
            })
            .collect::<Vec<_>>();

        for (i, zi) in individual_responses.iter().enumerate() {
            let (_, pk, _, commitment) = &individual_keys[i];
            assert!(verify_response(
                zi,
                &individual_inputs[i],
                &challenge,
                commitment.clone(),
                pk.clone()
            ))
        }

        let aggregate_response = aggregate_response(individual_responses);
        assert!(verify(
            aggregate_commitment.clone(),
            aggregate_response,
            Vec::new(),
            committee.clone(),
            md,
            Threshold { num: 1, denom: 1 }
        ));

        verify_ergoscript(
            committee,
            num_participants,
            aggregate_commitment,
            aggregate_response,
            vec![],
            md,
        );
    }

    #[test]
    fn verify_byzantine_ergoscript() {
        let num_participants = 128;
        let num_byzantine = 64;
        let mut rng = OsRng;
        let mut byz_indexes = vec![];
        loop {
            let rng = rng.gen_range(0usize..num_participants);
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine {
                break;
            }
        }
        let md = blake2b256_hash(b"foo");
        let individual_keys = (0..num_participants)
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let (commitment_sk, commitment) = schnorr_commitment_pair();
                (sk, pk, commitment_sk, commitment)
            })
            .collect::<Vec<_>>();
        let committee = individual_keys
            .iter()
            .map(|(_, pk, _, _)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = individual_keys
            .iter()
            .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
            individual_inputs.clone(),
        );
        let aggregate_commitment = aggregate_commitment(
            individual_keys
                .iter()
                .map(|(_, _, _, commitment)| commitment.clone())
                .collect(),
        );
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let (byz_keys, active_keys): (Vec<_>, Vec<_>) = individual_keys
            .clone()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| byz_indexes.contains(i));
        let individual_responses_subset = active_keys
            .iter()
            .map(|(i, (sk, _, commitment_sk, _))| {
                (
                    *i,
                    response(
                        commitment_sk.clone(),
                        sk.clone(),
                        challenge,
                        individual_inputs[*i],
                    ),
                )
            })
            .collect::<Vec<_>>();
        for (i, zi) in individual_responses_subset.iter() {
            let (_, pk, _, commitment) = &individual_keys[*i];
            assert!(verify_response(
                zi,
                &individual_inputs[*i],
                &challenge,
                commitment.clone(),
                pk.clone()
            ))
        }
        let aggregate_response =
            aggregate_response(individual_responses_subset.into_iter().map(|(_, x)| x).collect());
        let exclusion_set = byz_keys
            .iter()
            .map(|(i, (_, _, sk, commitment))| {
                (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md))))
            })
            .collect::<Vec<_>>();
        let threshold = Threshold { num: 2, denom: 4 };
        assert!(verify(
            aggregate_commitment.clone(),
            aggregate_response,
            exclusion_set.clone(),
            committee.clone(),
            md,
            threshold,
        ));
        let exclusion_set: Vec<_> = exclusion_set
            .into_iter()
            .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
            .collect();
        verify_ergoscript(
            committee,
            (num_participants * threshold.num / threshold.denom) as i32,
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            md,
        );
    }

    fn verify_ergoscript(
        committee: Vec<PublicKey>,
        threshold: i32,
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
        md: Blake2bDigest256,
    ) {
        let committee_lit = Literal::from(
            committee
                .into_iter()
                .map(|p| EcPoint::from(k256::PublicKey::from(p).to_projective()))
                .collect::<Vec<_>>(),
        );

        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: committee_lit,
        };

        let serialized_aggregate_commitment =
            Constant::from(EcPoint::from(ProjectivePoint::from(aggregate_commitment)));

        let s_biguint = scalar_to_biguint(aggregate_response);
        println!("# bytes: {}", s_biguint.to_bytes_be().len());
        let upper = BigUint::from_bytes_be(&s_biguint.to_bytes_be()[..16]);
        let upper_256 = BigInt256::try_from(upper).unwrap();
        assert_eq!(upper_256.sign(), Sign::Plus);
        let lower = BigUint::from_bytes_be(&s_biguint.to_bytes_be()[16..]);
        let lower_256 = BigInt256::try_from(lower).unwrap();
        assert_eq!(lower_256.sign(), Sign::Plus);

        let mut aggregate_response_bytes = upper_256.to_signed_bytes_be();
        // Need this variable because we could add an extra byte to the encoding for signed-representation.
        let first_len = aggregate_response_bytes.len() as i32;
        aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

        // Script URL: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBtZXNzYWdlICAgICAgICAgICAgICA9IElOUFVUUygwKS5SNFtDb2xsW0J5dGVdXS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgICAgICAgPSBJTlBVVFMoMCkuUjVbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgZ3JvdXBFbGVtZW50SWRlbnRpdHkgPSBJTlBVVFMoMCkuUjZbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgY29tbWl0dGVlICAgICAgICAgICAgPSBJTlBVVFMoMCkuUjdbQ29sbFtHcm91cEVsZW1lbnRdXS5nZXQKICB2YWwgdGhyZXNob2xkICAgICAgICAgICAgPSBJTlBVVFMoMCkuUjhbSW50XS5nZXQKCiAgdmFsIHZlcmlmaWNhdGlvbkRhdGEgPQogICAgZ2V0VmFyW0NvbGxbCiAgICAgICgKICAgICAgICAoSW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSksCiAgICAgICAgKChDb2xsW0J5dGVdLCBJbnQpLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkKICAgICAgKV1dKDApLmdldAogIHZhbCBhZ2dyZWdhdGVSZXNwb25zZVJhdyA9IGdldFZhclsoQ29sbFtCeXRlXSwgSW50KV0oMSkuZ2V0IC8vIHoKICB2YWwgYWdncmVnYXRlQ29tbWl0bWVudCA9IGdldFZhcltHcm91cEVsZW1lbnRdKDIpLmdldCAvLyBZCiAKICAvLyBQZXJmb3JtcyBleHBvbmVudGlhdGlvbiBvZiBhIEdyb3VwRWxlbWVudCBieSBhbiB1bnNpZ25lZCAyNTZiaXQKICAvLyBpbnRlZ2VyIEkgdXNpbmcgdGhlIGZvbGxvd2luZyBkZWNvbXBvc2l0aW9uIG9mIEk6CiAgLy8gTGV0IGUgPSAoZywgKGIsIG4pKS4gVGhlbiB0aGlzIGZ1bmN0aW9uIGNvbXB1dGVzOgogIC8vCiAgLy8gICBnXkkgPT0gKGdeYigwLG4pKV5wICogZ14oYihuLi4pKQogIC8vIHdoZXJlCiAgLy8gIC0gYigwLG4pIGlzIHRoZSBmaXJzdCBuIGJ5dGVzIG9mIGEgcG9zaXRpdmUgQmlnSW50IGBVYAogIC8vICAtIGIobi4uKSBhcmUgdGhlIHJlbWFpbmluZyBieXRlcyBzdGFydGluZyBmcm9tIGluZGV4IG4uIFRoZXNlIGJ5dGVzCiAgLy8gICAgYWxzbyByZXByZXNlbnQgYSBwb3NpdGl2ZSBCaWdJbnQgYExgLgogIC8vICAtIHAgaXMgMzQwMjgyMzY2OTIwOTM4NDYzNDYzMzc0NjA3NDMxNzY4MjExNDU2IGJhc2UgMTAuCiAgLy8gIC0gSSA9PSBVICogcCArIEwKICBkZWYgbXlFeHAoZTogKEdyb3VwRWxlbWVudCwgKENvbGxbQnl0ZV0sIEludCkpKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCB4ID0gZS5fMQogICAgdmFsIHkgPSBlLl8yLl8xCiAgICB2YWwgbGVuID0gZS5fMi5fMgogICAgdmFsIHVwcGVyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZSgwLCBsZW4pKQogICAgdmFsIGxvd2VyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZShsZW4sIHkuc2l6ZSkpCgogICAgLy8gVGhlIGZvbGxvd2luZyB2YWx1ZSBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZS0xMC4KICAgIHZhbCBwID0gYnl0ZUFycmF5VG9CaWdJbnQoZnJvbUJhc2U2NCgiQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKSkKICAgCiAgICB4LmV4cCh1cHBlcikuZXhwKHApLm11bHRpcGx5KHguZXhwKGxvd2VyKSkKICB9CgogIC8vIENvbnZlcnRzIGEgYmlnLWVuZGlhbiBieXRlIHJlcHJlc2VudGF0aW9uIG9mIGFuIHVuc2lnbmVkIGludGVnZXIgaW50byBpdHMKICAvLyBlcXVpdmFsZW50IHNpZ25lZCByZXByZXNlbnRhdGlvbgogIGRlZiB0b1NpZ25lZEJ5dGVzKGI6IENvbGxbQnl0ZV0pIDogQ29sbFtCeXRlXSA9IHsKICAgIC8vIE5vdGUgdGhhdCBhbGwgaW50ZWdlcnMgKGluY2x1ZGluZyBCeXRlKSBpbiBFcmdvc2NyaXB0IGFyZSBzaWduZWQuIEluIHN1Y2gKICAgIC8vIGEgcmVwcmVzZW50YXRpb24sIHRoZSBtb3N0LXNpZ25pZmljYW50IGJpdCAoTVNCKSBpcyB1c2VkIHRvIHJlcHJlc2VudCB0aGUKICAgIC8vIHNpZ247IDAgZm9yIGEgcG9zaXRpdmUgaW50ZWdlciBhbmQgMSBmb3IgbmVnYXRpdmUuIE5vdyBzaW5jZSBgYmAgaXMgYmlnLQogICAgLy8gZW5kaWFuLCB0aGUgTVNCIHJlc2lkZXMgaW4gdGhlIGZpcnN0IGJ5dGUgYW5kIE1TQiA9PSAxIGluZGljYXRlcyB0aGF0IGV2ZXJ5CiAgICAvLyBiaXQgaXMgdXNlZCB0byBzcGVjaWZ5IHRoZSBtYWduaXR1ZGUgb2YgdGhlIGludGVnZXIuIFRoaXMgbWVhbnMgdGhhdCBhbgogICAgLy8gZXh0cmEgMC1iaXQgbXVzdCBiZSBwcmVwZW5kZWQgdG8gYGJgIHRvIHJlbmRlciBpdCBhIHZhbGlkIHBvc2l0aXZlIHNpZ25lZAogICAgLy8gaW50ZWdlci4KICAgIC8vCiAgICAvLyBOb3cgc2lnbmVkIGludGVnZXJzIGFyZSBuZWdhdGl2ZSBpZmYgTVNCID09IDEsIGhlbmNlIHRoZSBjb25kaXRpb24gYmVsb3cuCiAgICBpZiAoYigwKSA8IDAgKSB7CiAgICAgICAgQ29sbCgwLnRvQnl0ZSkuYXBwZW5kKGIpCiAgICB9IGVsc2UgewogICAgICAgIGIKICAgIH0KICB9CgogIC8vIENvbXB1dGVzIGFfaSA9IEgoWF8xLCBYXzIsLi4sIFhfbjsgWF9pKQogIGRlZiBjYWxjQShlOiAoQ29sbFtHcm91cEVsZW1lbnRdLCBJbnQpKSA6IChDb2xsW0J5dGVdLCBJbnQpID0gewogICAgdmFsIGNvbW1pdHRlZU1lbWJlcnMgPSBlLl8xCiAgICB2YWwgaSA9IGUuXzIKICAgIHZhbCBieXRlcyA9IGNvbW1pdHRlZU1lbWJlcnMKICAgICAgLnNsaWNlKDEsIGNvbW1pdHRlZU1lbWJlcnMuc2l6ZSkKICAgICAgLmZvbGQoCiAgICAgICAgY29tbWl0dGVlTWVtYmVycygwKS5nZXRFbmNvZGVkLAogICAgICAgIHsgKGI6IENvbGxbQnl0ZV0sIGVsZW06IEdyb3VwRWxlbWVudCkgPT4gYi5hcHBlbmQoZWxlbS5nZXRFbmNvZGVkKSB9CiAgICAgICkKICAgIHZhbCByYXcgPSBibGFrZTJiMjU2KGJ5dGVzLmFwcGVuZChjb21taXR0ZWVNZW1iZXJzKGkpLmdldEVuY29kZWQpKQogICAgdmFsIGZpcnN0SW50ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwxNikpCiAgICB2YWwgY29uY2F0Qnl0ZXMgPSBmaXJzdEludC5hcHBlbmQodG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMTYscmF3LnNpemUpKSkKICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3RJbnQuc2l6ZQogICAgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKQogIH0KICAKICAvLyBDb21wdXRlcyBYfiA9IFhfMF57YV8wfSAqIFhfMV57YV8xfSAqIC4uLiAqIFhfe24tMX1ee2Ffe24tMX19CiAgZGVmIGNhbGNGdWxsQWdncmVnYXRlS2V5KGNvbW1pdHRlZU1lbWJlcnM6IENvbGxbR3JvdXBFbGVtZW50XSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICBjb21taXR0ZWVNZW1iZXJzLmZvbGQoCiAgICAgIChncm91cEVsZW1lbnRJZGVudGl0eSwgMCksCiAgICAgIHsgKGFjYzogKEdyb3VwRWxlbWVudCwgSW50ICksIHg6IEdyb3VwRWxlbWVudCkgPT4KICAgICAgICAgIHZhbCB4X2FjYyA9IGFjYy5fMQogICAgICAgICAgdmFsIGkgPSBhY2MuXzIKICAgICAgICAgICh4X2FjYy5tdWx0aXBseShteUV4cCgoeCwgY2FsY0EoKGNvbW1pdHRlZU1lbWJlcnMsIGkpKSkpKSwgaSArIDEpCiAgICAgIH0KICAgICkuXzEKICB9CgogIC8vIENvbXB1dGVzIFgnCiAgZGVmIGNhbGNQYXJ0aWFsQWdncmVnYXRlS2V5KGU6IChDb2xsW0dyb3VwRWxlbWVudF0sIENvbGxbSW50XSkpIDogR3JvdXBFbGVtZW50ID0gewogICAgdmFsIGNvbW1pdHRlZU1lbWJlcnMgPSBlLl8xCiAgICB2YWwgZXhjbHVkZWRJbmRpY2VzID0gZS5fMgogICAgY29tbWl0dGVlTWVtYmVycy5mb2xkKAogICAgICAoZ3JvdXBFbGVtZW50SWRlbnRpdHksIDApLAogICAgICB7IChhY2M6IChHcm91cEVsZW1lbnQsIEludCksIHg6IEdyb3VwRWxlbWVudCkgPT4KICAgICAgICAgIHZhbCB4QWNjID0gYWNjLl8xCiAgICAgICAgICB2YWwgaSA9IGFjYy5fMgogICAgICAgICAgaWYgKGV4Y2x1ZGVkSW5kaWNlcy5leGlzdHMgeyAoaXg6IEludCkgPT4gaXggPT0gaSB9KSB7CiAgICAgICAgICAgICAoeEFjYywgaSArIDEpCiAgICAgICAgICB9IGVsc2UgewogICAgICAgICAgICAoeEFjYy5tdWx0aXBseShteUV4cCgoeCwgY2FsY0EoKGNvbW1pdHRlZU1lbWJlcnMsIGkpKSkpKSwgaSArIDEpCiAgICAgICAgICB9CiAgICAgICAgICAKICAgICAgfQogICAgKS5fMQogIH0KCiAgLy8gQ2FsY3VsYXRlcyBhZ2dyZWdhdGUgY29tbWl0bWVudCBZJwogIGRlZiBjYWxjQWdncmVnYXRlQ29tbWl0bWVudChjb21taXRtZW50czogQ29sbFtHcm91cEVsZW1lbnRdKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIGNvbW1pdG1lbnRzLmZvbGQoCiAgICAgIGdyb3VwRWxlbWVudElkZW50aXR5LAogICAgICB7IChhY2M6IEdyb3VwRWxlbWVudCwgeTogR3JvdXBFbGVtZW50KSA9PgogICAgICAgICAgYWNjLm11bHRpcGx5KHkpCiAgICAgIH0KICAgICkgIAogIH0KCiAgZGVmIGVuY29kZVVuc2lnbmVkMjU2Qml0SW50KGJ5dGVzOiBDb2xsW0J5dGVdKSA6IChDb2xsW0J5dGVdLCBJbnQpID0gewogICAgdmFsIGZpcnN0SW50ID0gdG9TaWduZWRCeXRlcyhieXRlcy5zbGljZSgwLDE2KSkKICAgIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0SW50LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKGJ5dGVzLnNsaWNlKDE2LGJ5dGVzLnNpemUpKSkKICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3RJbnQuc2l6ZQogICAgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKQogIH0KICAgIAogIC8vIEJJUC0wMzQwIHVzZXMgc28tY2FsbGVkIHRhZ2dlZCBoYXNoZXMKICB2YWwgY2hhbGxlbmdlVGFnID0gc2hhMjU2KENvbGwoNjYsIDczLCA4MCwgNDgsIDUxLCA1MiwgNDgsIDQ3LCA5OSwgMTA0LCA5NywgMTA4LCAxMDgsIDEwMSwgMTEwLCAxMDMsIDEwMSkubWFwIHsgKHg6SW50KSA9PiB4LnRvQnl0ZSB9KQogIAoKICAvLyBjCiAgdmFsIGNoYWxsZW5nZVJhdyA9IGJsYWtlMmIyNTYoY2FsY0Z1bGxBZ2dyZWdhdGVLZXkoY29tbWl0dGVlKS5nZXRFbmNvZGVkICsrIGFnZ3JlZ2F0ZUNvbW1pdG1lbnQuZ2V0RW5jb2RlZCArKyBtZXNzYWdlICkKICB2YWwgY2hhbGxlbmdlICAgID0gZW5jb2RlVW5zaWduZWQyNTZCaXRJbnQoY2hhbGxlbmdlUmF3KQoKICB2YWwgZXhjbHVkZWRJbmRpY2VzID0gdmVyaWZpY2F0aW9uRGF0YS5tYXAgeyAoZTogKChJbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSwgKChDb2xsW0J5dGVdLCBJbnQpLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkpKSA9PgogICAgZS5fMS5fMSAKICB9CgogIHZhbCBleGNsdWRlZENvbW1pdG1lbnRzID0gdmVyaWZpY2F0aW9uRGF0YS5tYXAgeyAoZTogKChJbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSwgKChDb2xsW0J5dGVdLCBJbnQpLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkpKSA9PgogICAgZS5fMS5fMi5fMSAKICB9CgogIHZhbCBZRGFzaCA9IGNhbGNBZ2dyZWdhdGVDb21taXRtZW50KGV4Y2x1ZGVkQ29tbWl0bWVudHMpCgogIHZhbCBwYXJ0aWFsQWdncmVnYXRlS2V5ID0gY2FsY1BhcnRpYWxBZ2dyZWdhdGVLZXkoKGNvbW1pdHRlZSwgZXhjbHVkZWRJbmRpY2VzKSkKCiAgLy8gVmVyaWZpZXMgdGhhdCBZJypnXnogPT0gKFgnKV5jICogWQogIHZhbCB2ZXJpZnlBZ2dyZWdhdGVSZXNwb25zZSA9ICggbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCBhZ2dyZWdhdGVSZXNwb25zZVJhdykpLm11bHRpcGx5KFlEYXNoKSAKICAgICAgPT0gbXlFeHAoKHBhcnRpYWxBZ2dyZWdhdGVLZXksIGNoYWxsZW5nZSkpLm11bHRpcGx5KGFnZ3JlZ2F0ZUNvbW1pdG1lbnQpICkKCiAgdmFsIHZlcmlmeVNpZ25hdHVyZXNJbkV4Y2x1c2lvblNldCA9CiAgICB2ZXJpZmljYXRpb25EYXRhLmZvcmFsbCB7IChlOiAoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSkpID0+CiAgICAgIHZhbCBwdWJLZXlUdXBsZSA9IGUuXzEuXzIKICAgICAgdmFsIHMgID0gZS5fMi5fMQogICAgICB2YWwgcmVzcG9uc2VUdXBsZSA9IGUuXzIuXzIKCiAgICAgIHZhbCBwdWJLZXkgICAgICAgICA9IHB1YktleVR1cGxlLl8xIC8vIFlfaQogICAgICB2YWwgcGtCeXRlcyAgICAgICAgPSBwdWJLZXlUdXBsZS5fMiAvLyBlbmNvZGVkIHgtY29vcmRpbmF0ZSBvZiBZX2kKICAgICAgdmFsIHJlc3BvbnNlICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMSAvLyBSIGluIEJJUC0wMzQwCiAgICAgIHZhbCByQnl0ZXMgICAgICAgICA9IHJlc3BvbnNlVHVwbGUuXzIgLy8gQnl0ZSByZXByZXNlbnRhdGlvbiBvZiAncicKCgogICAgICB2YWwgcmF3ID0gc2hhMjU2KGNoYWxsZW5nZVRhZyArKyBjaGFsbGVuZ2VUYWcgKysgckJ5dGVzICsrIHBrQnl0ZXMgKysgbWVzc2FnZSkKIAogICAgICAvLyBOb3RlIHRoYXQgdGhlIG91dHB1dCBvZiBTSEEyNTYgaXMgYSBjb2xsZWN0aW9uIG9mIGJ5dGVzIHRoYXQgcmVwcmVzZW50cyBhbiB1bnNpZ25lZCAyNTZiaXQgaW50ZWdlci4gCiAgICAgIHZhbCBmaXJzdCA9IHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDAsMTYpKQogICAgICB2YWwgY29uY2F0Qnl0ZXMgPSBmaXJzdC5hcHBlbmQodG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMTYscmF3LnNpemUpKSkKICAgICAgdmFsIGZpcnN0SW50TnVtQnl0ZXMgPSBmaXJzdC5zaXplCiAgICAgIG15RXhwKChncm91cEdlbmVyYXRvciwgcykpID09ICBteUV4cCgocHViS2V5LCAoY29uY2F0Qnl0ZXMsIGZpcnN0SW50TnVtQnl0ZXMpKSkubXVsdGlwbHkocmVzcG9uc2UpCiAgICB9CgogIHZhbCB2ZXJpZnlUaHJlc2hvbGQgPSAoY29tbWl0dGVlLnNpemUgLSB2ZXJpZmljYXRpb25EYXRhLnNpemUpID49IHRocmVzaG9sZAoKICBzaWdtYVByb3AgKAogICAgdmVyaWZ5QWdncmVnYXRlUmVzcG9uc2UgJiYKICAgIHZlcmlmeVNpZ25hdHVyZXNJbkV4Y2x1c2lvblNldCAmJgogICAgdmVyaWZ5VGhyZXNob2xkCiAgKQp9
        const SCRIPT_BYTES: &str = "Zz2DApbVXBhupn1wpmxU9njeB6PD4qsi8dxQLMBZ1JML5d6hmQgG2dZiBvscwaBCR82gSXjy3zsGYyStJV9rhFVSNi39YfaPwAC6NpVKpaMweKYFkphqx6h5dGL3hEznD3dUe3e8pUPjZQhxRdkZSQcwCocUyFVJaftJx7X4RYj3J4emqXv8pNSkUhbs4UHeftzSbr9bamc5qDfKdafkn9JqQHuJ9yEnhXr5bnXXC7LwTdyeSdDmTfXMREfRMmmFBNLRko3GKxpx7G3TACmTtJvmJe2C3yPW3a1FNUck58C6FcLXXSRwr7oMCMYGhRCig3MHVKLDiGyAHCEAXLojMhoejoSNBhbGZT5DEgNH1pgC7bnp3JWPbHydGTM15H3Tvs4Xdc3e2G6fQTi3P2gFWSqVtbgAWLsjKLLWj6d7oQPVdMcgmZytb8RA2X9L1wDjnZ1EKxNpHbd6ZorMWqWe9sUVcMKkZUsE1Lx2tKb2dKSk2KbQRHT6JhqnAwaz8R6RFZrbthJ843bQXRVuWzLSNjwJdEG3C2So8kRMiWwu1tZxkNAcoJ5fqjiqe8dQynyDLDhjH1XeZ2Asm31MT8i5UEhbJLBafXqQjnuRXLEpv7iTzUjuDGAzCtVexfmhSrk9jCsc9e2BPGaUWVKruaKJm3EFH81m3cYPVvu21FAEox4kHDmJJhSDowuwX27dtnNpQVj7vTfk9hPLsg7dPb48PxzDz4HGXaPyC2rK3iEFshbfPME8ySKL7w4gaz8k83pfi9b3MGG3BvKp6ff8K5xcsG2mbQPuJ4eLtXYyiyPuquGv5Y9s7ZRSCUMYZQZGb2ntTpUiS4gveWrcWvR1QWU4npx8T8TEYdBj6ybfkW9hNTUvXRRX9MJp8EMFTjXcaX9qLUdwCMFVrHDxzSLmMqCBseksFWx92gmVkD5XUCvz4wrMtmd1n2sZeABGnN6iWpG1DQGLtd97vc8dvGogqM3u2QKjzcvrqZSVmtHYAgDEtuDNZu9Do7MY9Nj8V7z2QmM2HmUJVJTGEEdQ9eBxiP5wbw5RcNrhY2dwkdMH6PPJoVRzsLj9GVH4VTNDZDsWBqSwAq2vxKxaiWV4EjQDz9kghoufQz5GxgxQPFKu5GV2559jbhm8u467dDay86XqWU3LUHEAzzeXcY6yX9yZAryiZ6TsxJoQmBRXZFbW2J5pNq";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let mut registers = HashMap::new();

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(md.as_ref().to_vec()));
        registers.insert(NonMandatoryRegisterId::R5, Constant::from(generator()));
        registers.insert(
            NonMandatoryRegisterId::R6,
            Constant::from(EcPoint::from(ProjectivePoint::IDENTITY)),
        );
        registers.insert(NonMandatoryRegisterId::R7, serialized_committee);
        registers.insert(NonMandatoryRegisterId::R8, threshold.into());
        let mut values = IndexMap::new();
        let s_tuple: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();
        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        values.insert(0, exclusion_set_data);
        values.insert(1, s_tuple);
        values.insert(2, serialized_aggregate_commitment);
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
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });
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
}
