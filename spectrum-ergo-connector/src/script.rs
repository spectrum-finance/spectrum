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
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBtZXNzYWdlICAgICAgICA9IElOUFVUUygwKS5SNFtDb2xsW0J5dGVdXS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgPSBJTlBVVFMoMCkuUjVbR3JvdXBFbGVtZW50XS5nZXQKCiAgdmFsIHZlcmlmaWNhdGlvbkRhdGEgPSBnZXRWYXJbQ29sbFsoKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpICldXSgwKS5nZXQKIAogIC8vIFBlcmZvcm1zIGV4cG9uZW50aWF0aW9uIG9mIGEgR3JvdXBFbGVtZW50IGJ5IGFuIHVuc2lnbmVkIDI1NmJpdAogIC8vIGludGVnZXIgSSB1c2luZyB0aGUgZm9sbG93aW5nIGRlY29tcG9zaXRpb24gb2YgSToKICAvLyBMZXQgZSA9IChnLCAoYiwgbikpLiBUaGVuIHRoaXMgZnVuY3Rpb24gY29tcHV0ZXM6CiAgLy8KICAvLyAgIGdeSSA9PSAoZ15iKDAsbikpXnAgKiBnXihiKG4uLikpCiAgLy8gd2hlcmUKICAvLyAgLSBiKDAsbikgaXMgdGhlIGZpcnN0IG4gYnl0ZXMgb2YgYSBwb3NpdGl2ZSBCaWdJbnQgYFVgCiAgLy8gIC0gYihuLi4pIGFyZSB0aGUgcmVtYWluaW5nIGJ5dGVzIHN0YXJ0aW5nIGZyb20gaW5kZXggbi4gVGhlc2UgYnl0ZXMKICAvLyAgICBhbHNvIHJlcHJlc2VudCBhIHBvc2l0aXZlIEJpZ0ludCBgTGAuCiAgLy8gIC0gcCBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZSAxMC4KICAvLyAgLSBJID09IFUgKiBwICsgTAogIGRlZiBteUV4cChlOiAoR3JvdXBFbGVtZW50LCAoQ29sbFtCeXRlXSwgSW50KSkpIDogR3JvdXBFbGVtZW50ID0gewogICAgdmFsIHggPSBlLl8xCiAgICB2YWwgeSA9IGUuXzIuXzEKICAgIHZhbCBsZW4gPSBlLl8yLl8yCiAgICB2YWwgdXBwZXIgPSBieXRlQXJyYXlUb0JpZ0ludCh5LnNsaWNlKDAsIGxlbikpCiAgICB2YWwgbG93ZXIgPSBieXRlQXJyYXlUb0JpZ0ludCh5LnNsaWNlKGxlbiwgeS5zaXplKSkKCiAgICAvLyBUaGUgZm9sbG93aW5nIHZhbHVlIGlzIDM0MDI4MjM2NjkyMDkzODQ2MzQ2MzM3NDYwNzQzMTc2ODIxMTQ1NiBiYXNlLTEwLgogICAgdmFsIHAgPSBieXRlQXJyYXlUb0JpZ0ludChmcm9tQmFzZTY0KCJBUUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIpKQogICAKICAgIHguZXhwKHVwcGVyKS5leHAocCkubXVsdGlwbHkoeC5leHAobG93ZXIpKQogIH0KCiAgLy8gQ29udmVydHMgYSBiaWctZW5kaWFuIGJ5dGUgcmVwcmVzZW50YXRpb24gb2YgYW4gdW5zaWduZWQgaW50ZWdlciBpbnRvIGl0cwogIC8vIGVxdWl2YWxlbnQgc2lnbmVkIHJlcHJlc2VudGF0aW9uCiAgZGVmIHRvU2lnbmVkQnl0ZXMoYjogQ29sbFtCeXRlXSkgOiBDb2xsW0J5dGVdID0gewogICAgLy8gTm90ZSB0aGF0IGFsbCBpbnRlZ2VycyAoaW5jbHVkaW5nIEJ5dGUpIGluIEVyZ29zY3JpcHQgYXJlIHNpZ25lZC4gSW4gc3VjaAogICAgLy8gYSByZXByZXNlbnRhdGlvbiwgdGhlIG1vc3Qtc2lnbmlmaWNhbnQgYml0IChNU0IpIGlzIHVzZWQgdG8gcmVwcmVzZW50IHRoZQogICAgLy8gc2lnbjsgMCBmb3IgYSBwb3NpdGl2ZSBpbnRlZ2VyIGFuZCAxIGZvciBuZWdhdGl2ZS4gTm93IHNpbmNlIGBiYCBpcyBiaWctCiAgICAvLyBlbmRpYW4sIHRoZSBNU0IgcmVzaWRlcyBpbiB0aGUgZmlyc3QgYnl0ZSBhbmQgTVNCID09IDEgaW5kaWNhdGVzIHRoYXQgZXZlcnkKICAgIC8vIGJpdCBpcyB1c2VkIHRvIHNwZWNpZnkgdGhlIG1hZ25pdHVkZSBvZiB0aGUgaW50ZWdlci4gVGhpcyBtZWFucyB0aGF0IGFuCiAgICAvLyBleHRyYSAwLWJpdCBtdXN0IGJlIHByZXBlbmRlZCB0byBgYmAgdG8gcmVuZGVyIGl0IGEgdmFsaWQgcG9zaXRpdmUgc2lnbmVkCiAgICAvLyBpbnRlZ2VyLgogICAgLy8KICAgIC8vIE5vdyBzaWduZWQgaW50ZWdlcnMgYXJlIG5lZ2F0aXZlIGlmZiBNU0IgPT0gMSwgaGVuY2UgdGhlIGNvbmRpdGlvbiBiZWxvdy4KICAgIGlmIChiKDApIDwgMCApIHsKICAgICAgICBDb2xsKDAudG9CeXRlKS5hcHBlbmQoYikKICAgIH0gZWxzZSB7CiAgICAgICAgYgogICAgfQogIH0KCiAgLy8gQ29tcHV0ZXMgYV9pID0gSChYXzEsIFhfMiwuLiwgWF9uOyBYX2kpCiAgZGVmIGNhbGNBKGU6IChDb2xsW0dyb3VwRWxlbWVudF0sIEludCkpIDogKENvbGxbQnl0ZV0sIEludCkgPSB7CiAgICB2YWwgY29tbWl0dGVlTWVtYmVycyA9IGUuXzEKICAgIHZhbCBpID0gZS5fMgogICAgdmFsIGJ5dGVzID0gY29tbWl0dGVlTWVtYmVycy5mb2xkKENvbGxbQnl0ZV0oKSwgeyhiOiBDb2xsW0J5dGVdLCBlbGVtOiBHcm91cEVsZW1lbnQpID0+IGIuYXBwZW5kKGVsZW0uZ2V0RW5jb2RlZCkgfSkKICAgIHZhbCByYXcgPSBibGFrZTJiMjU2KGJ5dGVzLmFwcGVuZChjb21taXR0ZWVNZW1iZXJzKGkpLmdldEVuY29kZWQpKQogICAgdmFsIGZpcnN0SW50ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwxNikpCiAgICB2YWwgY29uY2F0Qnl0ZXMgPSBmaXJzdEludC5hcHBlbmQodG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMTYscmF3LnNpemUpKSkKICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3RJbnQuc2l6ZQogICAgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKQogIH0KICAKICAvLyBDb21wdXRlcyBYfiA9IFhfMF57YV8wfSAqIFhfMV57YV8xfSAqIC4uLiAqIFhfe24tMX1ee2Ffe24tMX19CiAgZGVmIGNhbGNGdWxsQWdncmVnYXRlS2V5KGNvbW1pdHRlZU1lbWJlcnM6IENvbGxbR3JvdXBFbGVtZW50XSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICB2YWwgWF8wID0gY29tbWl0dGVlTWVtYmVycygwKQogICAgdmFsIFhfMF9hID0gbXlFeHAoKFhfMCwgY2FsY0EoKGNvbW1pdHRlZU1lbWJlcnMsIDApKSkpCiAgICBjb21taXR0ZWVNZW1iZXJzLnNsaWNlKDEsIGNvbW1pdHRlZU1lbWJlcnMuc2l6ZSkuZm9sZCgKICAgICAgKFhfMF9hLCAwKSwKICAgICAgeyAoYWNjOiAoR3JvdXBFbGVtZW50LCBJbnQgKSwgeDogR3JvdXBFbGVtZW50KSA9PgogICAgICAgICAgdmFsIHhfYWNjID0gYWNjLl8xCiAgICAgICAgICB2YWwgaSA9IGFjYy5fMiArIDEKICAgICAgICAgICh4X2FjYy5tdWx0aXBseShteUV4cCgoeCwgY2FsY0EoKGNvbW1pdHRlZU1lbWJlcnMsIGkpKSkpKSwgaSkKICAgICAgfQogICAgKS5fMQogIH0KCiAgLy8gQ29tcHV0ZXMgWCcKICBkZWYgY2FsY1BhcnRpYWxBZ2dyZWdhdGVLZXkoZTogKENvbGxbR3JvdXBFbGVtZW50XSwgQ29sbFtJbnRdKSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICB2YWwgY29tbWl0dGVlTWVtYmVycyA9IGUuXzEKICAgIHZhbCBleGNsdWRlZEluZGljZXMgPSBlLl8yCiAgICB2YWwgZmlyc3RJeCA9IGV4Y2x1ZGVkSW5kaWNlcygwKQogICAgdmFsIGZpcnN0X1hfYSA9IG15RXhwKChjb21taXR0ZWVNZW1iZXJzKGZpcnN0SXgpLCBjYWxjQSgoY29tbWl0dGVlTWVtYmVycywgZmlyc3RJeCkpKSkKICAgIGV4Y2x1ZGVkSW5kaWNlcy5zbGljZSgxLCBleGNsdWRlZEluZGljZXMuc2l6ZSkuZm9sZCgKICAgICAgZmlyc3RfWF9hLAogICAgICB7IChhY2M6IEdyb3VwRWxlbWVudCwgaTogSW50KSA9PgogICAgICAgICAgYWNjLm11bHRpcGx5KG15RXhwKChjb21taXR0ZWVNZW1iZXJzKGkpLCBjYWxjQSgoY29tbWl0dGVlTWVtYmVycywgaSkpKSkpCiAgICAgIH0KICAgICkKICB9CgogIC8vIENhbGN1bGF0ZXMgYWdncmVnYXRlIGNvbW1pdG1lbnQgWScKICBkZWYgY2FsY0FnZ3JlZ2F0ZUNvbW1pdG1lbnQoY29tbWl0bWVudHM6IENvbGxbR3JvdXBFbGVtZW50XSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICBjb21taXRtZW50cy5zbGljZSgxLCBjb21taXRtZW50cy5zaXplKS5mb2xkKAogICAgICBjb21taXRtZW50cygwKSwKICAgICAgeyAoYWNjOiBHcm91cEVsZW1lbnQsIHk6IEdyb3VwRWxlbWVudCkgPT4KICAgICAgICAgIGFjYy5tdWx0aXBseSh5KQogICAgICB9CiAgICApICAKICB9CiAgICAKICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgdmFsIGNoYWxsZW5nZVRhZyA9IHNoYTI1NihDb2xsKDY2LCA3MywgODAsIDQ4LCA1MSwgNTIsIDQ4LCA0NywgOTksIDEwNCwgOTcsIDEwOCwgMTA4LCAxMDEsIDExMCwgMTAzLCAxMDEpLm1hcCB7ICh4OkludCkgPT4geC50b0J5dGUgfSkKCgogIHNpZ21hUHJvcCAoCiAgICB2ZXJpZmljYXRpb25EYXRhLmZvcmFsbCB7IChlOiAoKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpKSkgPT4KICAgICAgdmFsIHB1YktleVR1cGxlID0gZS5fMQogICAgICB2YWwgcyAgPSBlLl8yLl8xCiAgICAgIHZhbCByZXNwb25zZVR1cGxlID0gZS5fMi5fMgoKICAgICAgdmFsIHB1YktleSAgICAgICAgID0gcHViS2V5VHVwbGUuXzEgLy8gUAogICAgICB2YWwgcGtCeXRlcyAgICAgICAgPSBwdWJLZXlUdXBsZS5fMiAvLyBlbmNvZGVkIHgtY29vcmRpbmF0ZSBvZiBQCiAgICAgIHZhbCByZXNwb25zZSAgICAgICA9IHJlc3BvbnNlVHVwbGUuXzEgLy8gUiBpbiBCSVAtMDM0MAogICAgICB2YWwgckJ5dGVzICAgICAgICAgPSByZXNwb25zZVR1cGxlLl8yIC8vIEJ5dGUgcmVwcmVzZW50YXRpb24gb2YgJ3InCgoKICAgICAgdmFsIHJhdyA9IHNoYTI1NihjaGFsbGVuZ2VUYWcgKysgY2hhbGxlbmdlVGFnICsrIHJCeXRlcyArKyBwa0J5dGVzICsrIG1lc3NhZ2UpCiAKICAgICAgLy8gTm90ZSB0aGF0IHRoZSBvdXRwdXQgb2YgU0hBMjU2IGlzIGEgY29sbGVjdGlvbiBvZiBieXRlcyB0aGF0IHJlcHJlc2VudHMgYW4gdW5zaWduZWQgMjU2Yml0IGludGVnZXIuIAogICAgICB2YWwgZmlyc3QgPSB0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZSgwLDE2KSkKICAgICAgdmFsIGNvbmNhdEJ5dGVzID0gZmlyc3QuYXBwZW5kKHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDE2LHJhdy5zaXplKSkpCiAgICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3Quc2l6ZQogICAgICBteUV4cCgoZ3JvdXBHZW5lcmF0b3IsIHMpKSA9PSAgbXlFeHAoKHB1YktleSwgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKSkpLm11bHRpcGx5KHJlc3BvbnNlKQogICAgfQogICAgICAKICApCn0=
        const SCRIPT_BYTES: &str = "B65Hvsx55zWd2Mcs5MMitRNx4Nmkgpi2uhpExQKoWznLGxNFLun7V8wB2jmoJCYsBgqMSXxAT1efFBTPAEaCNUhKBxDRToMZDJCzPDZLbUbG5UorBG9cFAGyFxPSd4SdjAoNLaHFTCyioL9wQXfmZGuYxkumDXmq7ABf3NyAsLnnJn1TKgjLiFvcnchYcfdx2JzMnfPs58nNdXYmEYRk2ze5ouBxUYLNKeMGGFsdaKYrbLprtxbmMBuvL2eZWL766f5AvHQshiwyeHJk2A9g25UZ51PBfNsB1WweP5pPHiQoFnEYju1ycSrxjDvBQkTJovyprUbT3p8z69wadX1XmMPihnrSmGjQfr1kcBsdBafm12GZ1pt99KDz9UFrjRNrkpLSsNSTc1M6xmVHPUQWVCQuvTbtgvouxvMGUEisn6RJabyUPbCzeAk6qqdJW37xNUubHmkdeD7ivcSmE1dKtoU2M5LC4U3M8gBVmVTkpY95URpXm4Ch31JomP";

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

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(msg.to_vec()));
        registers.insert(NonMandatoryRegisterId::R5, Constant::from(generator()));
        // P from BIP-0340
        let pubkey_point = EcPoint::from(ProjectivePoint::from(signing_key.verifying_key().as_affine()));
        // The x-coordinate of P
        let pubkey_x_coords = signing_key.verifying_key().to_bytes().to_vec();

        let pubkey_tuple: Constant = (Constant::from(pubkey_point), Constant::from(pubkey_x_coords)).into();
        let s_tuple: Constant = (Constant::from(s_bytes), Constant::from(first_len)).into();
        let r_tuple: Constant = (
            Constant::from(EcPoint::from(r_point)),
            Constant::from(r.to_bytes().to_vec()),
        )
            .into();
        let s_r_tuple: Constant = (s_tuple, r_tuple).into();
        let elem: Constant = (pubkey_tuple, s_r_tuple).into();
        let elem_tpe = elem.tpe.clone();
        let coll: Constant = Constant {
            tpe: SType::SColl(Box::new(elem_tpe.clone())),
            v: Literal::Coll(CollKind::WrappedColl {
                elem_tpe,
                items: vec![elem.v],
            }),
        };

        let mut values = IndexMap::new();
        values.insert(0, coll);
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
