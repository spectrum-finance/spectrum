use std::{iter::repeat, time::Instant};

use blake2::Blake2b;
use bytes::Bytes;
use elliptic_curve::consts::U32;
use ergo_lib::{
    chain::{
        ergo_state_context::ErgoStateContext,
        transaction::{unsigned::UnsignedTransaction, DataInput, Transaction, TxId, TxIoVec, UnsignedInput},
    },
    ergo_chain_types::{Digest, EcPoint},
    ergotree_interpreter::sigma_protocol::prover::ContextExtension,
    ergotree_ir::{
        bigint256::BigInt256,
        chain::ergo_box::{box_value::BoxValue, BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisters},
        mir::{
            avl_tree_data::{AvlTreeData, AvlTreeFlags},
            constant::Constant,
        },
        serialization::SigmaSerializable,
    },
    wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext, Wallet},
};
use indexmap::IndexMap;
use k256::{ProjectivePoint, Scalar, SecretKey};
use num_bigint::{BigUint, Sign};
use rand::{rngs::OsRng, Rng};
use scorex_crypto_avltree::{
    authenticated_tree_ops::AuthenticatedTreeOps,
    batch_avl_prover::BatchAVLProver,
    batch_node::AVLTree,
    operation::{KeyValue, Operation},
};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::ProtoTermCell;
use spectrum_crypto::{digest::blake2b256_hash, pubkey::PublicKey};
use spectrum_handel::Threshold;
use spectrum_sigma::{
    crypto::{
        aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
        response, schnorr_commitment_pair, verify, verify_response,
    },
    AggregateCommitment, Commitment, Signature,
};

use spectrum_ergo_connector::script::{
    dummy_resolver, scalar_to_biguint, serialize_exclusion_set, ErgoCell, ErgoTermCell, ErgoTermCells,
    SignatureAggregationWithNotarizationElements,
};

use crate::VAULT_CONTRACT;

pub fn simulate_signature_aggregation_notarized_proofs(
    participant_secret_keys: Vec<SecretKey>,
    proto_term_cells: Vec<ProtoTermCell>,
    num_byzantine_nodes: usize,
    threshold: Threshold,
    max_miner_fee: i64,
) -> SignatureAggregationWithNotarizationElements {
    let mut rng = OsRng;
    let mut byz_indexes = vec![];
    if num_byzantine_nodes > 0 {
        loop {
            let rng = rng.gen_range(0usize..participant_secret_keys.len());
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine_nodes {
                break;
            }
        }
    }
    let individual_keys = participant_secret_keys
        .into_iter()
        .map(|sk| {
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

    let terminal_cells: Vec<_> = proto_term_cells
        .into_iter()
        .map(|p| ErgoTermCell::try_from(p).unwrap())
        .collect();

    let empty_tree = AVLTree::new(dummy_resolver, KEY_LENGTH, Some(VALUE_LENGTH));
    let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
    let initial_digest = prover.digest().unwrap().to_vec();

    for (i, cell) in terminal_cells.iter().enumerate() {
        let value = Bytes::copy_from_slice(blake2b256_hash(&cell.to_bytes()).as_ref());
        let key_bytes = ((i + 1) as i64).to_be_bytes();
        let key = Bytes::copy_from_slice(&key_bytes);
        let kv = KeyValue { key, value };
        let insert = Operation::Insert(kv.clone());
        prover.perform_one_operation(&insert).unwrap();
    }

    // Perform insertion for max_miner_fee
    {
        let key_bytes = ((terminal_cells.len() + 1) as i64).to_be_bytes();
        let key = Bytes::copy_from_slice(&key_bytes);
        let mut value_bytes = max_miner_fee.to_be_bytes().to_vec();
        // Need to pad to 32 bytes
        value_bytes.extend(repeat(0).take(24));
        let value = Bytes::copy_from_slice(&value_bytes);
        let kv = KeyValue { key, value };
        let insert = Operation::Insert(kv.clone());
        prover.perform_one_operation(&insert).unwrap();
    }

    let proof = prover.generate_proof().to_vec();
    let resulting_digest = prover.digest().unwrap().to_vec();
    let avl_tree_data = AvlTreeData {
        digest: Digest::<33>::try_from(initial_digest).unwrap(),
        tree_flags: AvlTreeFlags::new(true, false, false),
        key_length: KEY_LENGTH as u32,
        value_length_opt: Some(Box::new(VALUE_LENGTH as u32)),
    };

    let md = blake2b256_hash(&resulting_digest);

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
        .map(|(i, (_, _, sk, commitment))| (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md)))))
        .collect::<Vec<_>>();
    assert!(verify(
        aggregate_commitment.clone(),
        aggregate_response,
        exclusion_set.clone(),
        committee.clone(),
        md,
        threshold,
    ));
    let k256_exclusion_set: Vec<_> = exclusion_set
        .into_iter()
        .map(|(ix, pair)| {
            (
                ix,
                pair.map(|(c, s)| (c, Signature::from(k256::schnorr::Signature::from(s)))),
            )
        })
        .collect();
    SignatureAggregationWithNotarizationElements {
        aggregate_commitment,
        aggregate_response,
        exclusion_set: k256_exclusion_set,
        threshold,
        starting_avl_tree: avl_tree_data,
        proof,
        resulting_digest,
        terminal_cells,
        max_miner_fee,
    }
}

const KEY_LENGTH: usize = 8;
const VALUE_LENGTH: usize = 32;
