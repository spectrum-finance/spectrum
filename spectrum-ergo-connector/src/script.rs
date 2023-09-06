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

    use base64::prelude::BASE64_STANDARD_NO_PAD;
    use base64::Engine;
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
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature() {
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBwdWJLZXlUdXBsZSAgICA9IElOUFVUUygwKS5SNFsoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKV0uZ2V0CiAgdmFsIHMgICAgICAgICAgICAgID0gSU5QVVRTKDApLlI1WyhDb2xsW0J5dGVdLCBJbnQpXS5nZXQKICB2YWwgcmVzcG9uc2VUdXBsZSAgPSBJTlBVVFMoMCkuUjZbKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSldLmdldCAKICB2YWwgbWVzc2FnZSAgICAgICAgPSBJTlBVVFMoMCkuUjdbQ29sbFtCeXRlXV0uZ2V0CiAgdmFsIGdyb3VwR2VuZXJhdG9yID0gSU5QVVRTKDApLlI4W0dyb3VwRWxlbWVudF0uZ2V0CgogIHZhbCBwdWJLZXkgICAgICAgICA9IHB1YktleVR1cGxlLl8xIC8vIFAKICB2YWwgcGtCeXRlcyAgICAgICAgPSBwdWJLZXlUdXBsZS5fMiAvLyBlbmNvZGVkIHgtY29vcmRpbmF0ZSBvZiBQCiAgdmFsIHJlc3BvbnNlICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMSAvLyBSIGluIEJJUC0wMzQwCiAgdmFsIHJCeXRlcyAgICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMiAvLyBCeXRlIHJlcHJlc2VudGF0aW9uIG9mICdyJwoKICAKICAvLyBQZXJmb3JtcyBleHBvbmVudGlhdGlvbiBvZiBhIEdyb3VwRWxlbWVudCBieSBhbiB1bnNpZ25lZCAyNTZiaXQKICAvLyBpbnRlZ2VyIEkgdXNpbmcgdGhlIGZvbGxvd2luZyBkZWNvbXBvc2l0aW9uIG9mIEk6CiAgLy8gTGV0IGUgPSAoZywgKGIsIG4pKS4gVGhlbiB0aGlzIGZ1bmN0aW9uIGNvbXB1dGVzOgogIC8vCiAgLy8gICBnXkkgPT0gKGdeYigwLG4pKV5wICogZ14oYihuLi4pKQogIC8vIHdoZXJlCiAgLy8gIC0gYigwLG4pIGlzIHRoZSBmaXJzdCBuIGJ5dGVzIG9mIGEgcG9zaXRpdmUgQmlnSW50IGBVYAogIC8vICAtIGIobi4uKSBhcmUgdGhlIHJlbWFpbmluZyBieXRlcyBzdGFydGluZyBmcm9tIGluZGV4IG4uIFRoZXNlIGJ5dGVzCiAgLy8gICAgYWxzbyByZXByZXNlbnQgYSBwb3NpdGl2ZSBCaWdJbnQgYExgLgogIC8vICAtIHAgaXMgMzQwMjgyMzY2OTIwOTM4NDYzNDYzMzc0NjA3NDMxNzY4MjExNDU2IGJhc2UgMTAuCiAgLy8gIC0gSSA9PSBVICogcCArIEwKICBkZWYgbXlFeHAoZTogKEdyb3VwRWxlbWVudCwgKENvbGxbQnl0ZV0sIEludCkpKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCB4ID0gZS5fMQogICAgdmFsIHkgPSBlLl8yLl8xCiAgICB2YWwgbGVuID0gZS5fMi5fMgogICAgdmFsIHVwcGVyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZSgwLCBsZW4pKQogICAgdmFsIGxvd2VyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZShsZW4sIHkuc2l6ZSkpCgogICAgLy8gVGhlIGZvbGxvd2luZyB2YWx1ZSBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZS0xMC4KICAgIHZhbCBwID0gYnl0ZUFycmF5VG9CaWdJbnQoZnJvbUJhc2U2NCgiQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKSkKICAgCiAgICB4LmV4cCh1cHBlcikuZXhwKHApLm11bHRpcGx5KHguZXhwKGxvd2VyKSkKICB9CgogIC8vIENvbnZlcnRzIGEgYmlnLWVuZGlhbiBieXRlIHJlcHJlc2VudGF0aW9uIG9mIGFuIHVuc2lnbmVkIGludGVnZXIgaW50byBpdHMKICAvLyBlcXVpdmFsZW50IHNpZ25lZCByZXByZXNlbnRhdGlvbgogIGRlZiB0b1NpZ25lZEJ5dGVzKGI6IENvbGxbQnl0ZV0pIDogQ29sbFtCeXRlXSA9IHsKICAgIC8vIE5vdGUgdGhhdCBhbGwgaW50ZWdlcnMgKGluY2x1ZGluZyBCeXRlKSBpbiBFcmdvc2NyaXB0IGFyZSBzaWduZWQuIEluIHN1Y2gKICAgIC8vIGEgcmVwcmVzZW50YXRpb24sIHRoZSBtb3N0LXNpZ25pZmljYW50IGJpdCAoTVNCKSBpcyB1c2VkIHRvIHJlcHJlc2VudCB0aGUKICAgIC8vIHNpZ247IDAgZm9yIGEgcG9zaXRpdmUgaW50ZWdlciBhbmQgMSBmb3IgbmVnYXRpdmUuIE5vdyBzaW5jZSBgYmAgaXMgYmlnLQogICAgLy8gZW5kaWFuLCB0aGUgTVNCIHJlc2lkZXMgaW4gdGhlIGZpcnN0IGJ5dGUgYW5kIE1TQiA9PSAxIGluZGljYXRlcyB0aGF0IGV2ZXJ5CiAgICAvLyBiaXQgaXMgdXNlZCB0byBzcGVjaWZ5IHRoZSBtYWduaXR1ZGUgb2YgdGhlIGludGVnZXIuIFRoaXMgbWVhbnMgdGhhdCBhbgogICAgLy8gZXh0cmEgMC1iaXQgbXVzdCBiZSBwcmVwZW5kZWQgdG8gYGJgIHRvIHJlbmRlciBpdCBhIHZhbGlkIHBvc2l0aXZlIHNpZ25lZAogICAgLy8gaW50ZWdlci4KICAgIC8vCiAgICAvLyBOb3cgc2lnbmVkIGludGVnZXJzIGFyZSBuZWdhdGl2ZSBpZmYgTVNCID09IDEsIGhlbmNlIHRoZSBjb25kaXRpb24gYmVsb3cuCiAgICBpZiAoYigwKSA8IDAgKSB7CiAgICAgICAgQ29sbCgwLnRvQnl0ZSkuYXBwZW5kKGIpCiAgICB9IGVsc2UgewogICAgICAgIGIKICAgIH0KICB9CiAgCiAgICAKICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgdmFsIGNoYWxsZW5nZVRhZyA9IHNoYTI1NihDb2xsKDY2LCA3MywgODAsIDQ4LCA1MSwgNTIsIDQ4LCA0NywgOTksIDEwNCwgOTcsIDEwOCwgMTA4LCAxMDEsIDExMCwgMTAzLCAxMDEpLm1hcCB7ICh4OkludCkgPT4geC50b0J5dGUgfSkKICB2YWwgcmF3ID0gc2hhMjU2KGNoYWxsZW5nZVRhZyArKyBjaGFsbGVuZ2VUYWcgKysgckJ5dGVzICsrIHBrQnl0ZXMgKysgbWVzc2FnZSkKCiAgLy8gTm90ZSB0aGF0IHRoZSBvdXRwdXQgb2YgU0hBMjU2IGlzIGEgY29sbGVjdGlvbiBvZiBieXRlcyB0aGF0IHJlcHJlc2VudHMgYW4gdW5zaWduZWQgMjU2Yml0IGludGVnZXIuIAogIHZhbCBmaXJzdCA9IHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDAsMTYpKQogIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZSgxNixyYXcuc2l6ZSkpKQogIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3Quc2l6ZQoKICBzaWdtYVByb3AgKG15RXhwKChncm91cEdlbmVyYXRvciwgcykpID09ICBteUV4cCgocHViS2V5LCAoY29uY2F0Qnl0ZXMsIGZpcnN0SW50TnVtQnl0ZXMpKSkubXVsdGlwbHkocmVzcG9uc2UpKQp9
        const SCRIPT_BYTES: &str = "2uepSNTcPtZBDLuYC1AwzuuBjbHd1WZo9gcn4vWaaaA6iuyRyeAvQsH5YrmuWvcqdG96tq5v1r9nzuKSWFW5voYahwMEyGxfi3A5L9Rozg2QLPJWEH3AsuhKj1HjmZ8g1GH3uAXtrTmdvwJ65A1LjKYSts6S2QiZxt1nCRtg3FdmTzkZsYsDn2QHmHgU38mfR4B6j7QAN2zZn6ijMiteyySrFH6o9ANPzcxVWr6ZCcq1W2oytV88eomwcYVQuqvPuoxv5db8LwhmZ3gteWQQvEdFgiz4S3fGFf6tofEc6WkySVnFAfdFqoo8pgCE4YREpuwvkt6jrEL1up37C9MfGifyBdxfCzgKanYe1unqSc1Mr1KQG9CS5D4RLpqspUYDGw3guhMirKMe2B5ypLvEu75DabhP25nT6eKJYX5E5bFaTckaWxEL6frhBuHQ74VHNYJswtqZWjeVB12QYzEytX9Vi3P";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let msg = b"foo".as_slice();
        let mut rng = OsRng;
        let secret_key = SecretKey::random(&mut rng);
        let signing_key = SigningKey::from(secret_key);
        let signature = signing_key.sign(msg);
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
                .chain_update(signing_key.verifying_key().to_bytes())
                .chain_update(msg)
                .finalize(),
        );
        let s = NonZeroScalar::try_from(s_bytes).unwrap();

        // R
        let r_point = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &s,
            &ProjectivePoint::from(signing_key.verifying_key().as_affine()),
            &-e,
        );

        // The taproot signature satisfies:
        //     g ^ s == R * P^e
        // Note: `k256` uses additive notation for elliptic-curves, so we can compute the right
        // hand side with:
        //   r_point + ProjectivePoint::from(signing_key.verifying_key().as_affine()) * e;
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

        let mut registers = HashMap::new();

        // P from BIP-0340
        let pubkey_point = EcPoint::from(ProjectivePoint::from(signing_key.verifying_key().as_affine()));
        // The x-coordinate of P
        let pubkey_x_coords = signing_key.verifying_key().to_bytes().to_vec();
        registers.insert(
            NonMandatoryRegisterId::R4,
            (Constant::from(pubkey_point), Constant::from(pubkey_x_coords)).into(),
        );
        registers.insert(NonMandatoryRegisterId::R5, (s_bytes, first_len).into());
        registers.insert(
            NonMandatoryRegisterId::R6,
            (
                Constant::from(EcPoint::from(r_point)),
                Constant::from(r.to_bytes().to_vec()),
            )
                .into(),
        );
        registers.insert(NonMandatoryRegisterId::R7, Constant::from(msg.to_vec()));
        registers.insert(NonMandatoryRegisterId::R8, Constant::from(generator()));

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
