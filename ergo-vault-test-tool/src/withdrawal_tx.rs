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
    },
    wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext, Wallet},
};
use indexmap::IndexMap;
use k256::{schnorr::Signature, ProjectivePoint, Scalar, SecretKey};
use num_bigint::{BigUint, Sign};
use rand::{rngs::OsRng, Rng};
use scorex_crypto_avltree::{
    authenticated_tree_ops::AuthenticatedTreeOps,
    batch_avl_prover::BatchAVLProver,
    batch_node::AVLTree,
    operation::{KeyValue, Operation},
};
use spectrum_chain_connector::ProtoTermCell;
use spectrum_crypto::{digest::blake2b256_hash, pubkey::PublicKey};
use spectrum_handel::Threshold;
use spectrum_sigma::{
    crypto::{
        aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
        response, schnorr_commitment_pair, verify, verify_response,
    },
    AggregateCommitment, Commitment,
};

use spectrum_ergo_connector::script::{
    dummy_resolver, scalar_to_biguint, serialize_exclusion_set, ErgoTermCell, ErgoTermCells,
};

use crate::VAULT_CONTRACT;

pub struct SignatureAggregationWithNotarizationElements {
    aggregate_commitment: AggregateCommitment,
    aggregate_response: Scalar,
    exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
    committee: Vec<PublicKey>,
    threshold: Threshold,
    starting_avl_tree: AvlTreeData,
    proof: Vec<u8>,
    resulting_digest: Vec<u8>,
    terminal_cells: Vec<ErgoTermCell>,
    max_miner_fee: i64,
}

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
        .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
        .collect();
    SignatureAggregationWithNotarizationElements {
        aggregate_commitment,
        aggregate_response,
        exclusion_set: k256_exclusion_set,
        committee,
        threshold,
        starting_avl_tree: avl_tree_data,
        proof,
        resulting_digest,
        terminal_cells,
        max_miner_fee,
    }
}

pub fn verify_vault_contract_ergoscript_with_sigma_rust(
    inputs: SignatureAggregationWithNotarizationElements,
    ergo_state_context: ErgoStateContext,
    vault_utxo: ErgoBox,
    data_boxes: Vec<ErgoBox>,
    wallet: &Wallet,
    current_height: u32,
) -> Transaction {
    let SignatureAggregationWithNotarizationElements {
        aggregate_commitment,
        aggregate_response,
        exclusion_set,
        committee,
        threshold,
        starting_avl_tree,
        proof,
        resulting_digest,
        terminal_cells,
        max_miner_fee,
    } = inputs;

    let serialized_aggregate_commitment =
        Constant::from(EcPoint::from(ProjectivePoint::from(aggregate_commitment)));

    let s_biguint = scalar_to_biguint(aggregate_response);
    let biguint_bytes = s_biguint.to_bytes_be();
    if biguint_bytes.len() < 32 {
        println!("# bytes: {}", biguint_bytes.len());
    }
    let split = biguint_bytes.len() - 16;
    let upper = BigUint::from_bytes_be(&biguint_bytes[..split]);
    let upper_256 = BigInt256::try_from(upper).unwrap();
    assert_eq!(upper_256.sign(), Sign::Plus);
    let lower = BigUint::from_bytes_be(&biguint_bytes[split..]);
    let lower_256 = BigInt256::try_from(lower).unwrap();
    assert_eq!(lower_256.sign(), Sign::Plus);

    let mut aggregate_response_bytes = upper_256.to_signed_bytes_be();
    // VERY IMPORTANT: Need this variable because we could add an extra byte to the encoding
    // for signed-representation.
    let first_len = aggregate_response_bytes.len() as i32;
    aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

    let change_for_miner = BoxValue::try_from(max_miner_fee).unwrap();

    let md = blake2b256_hash(&resulting_digest);
    let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
    let aggregate_response: Constant = (
        Constant::from(aggregate_response_bytes),
        Constant::from(first_len),
    )
        .into();
    let num_participants = committee.len();
    let threshold = (num_participants * threshold.num / threshold.denom) as i32;
    let proof = Constant::from(proof);
    let avl_const = Constant::from(starting_avl_tree);

    // Create outboxes for terminal cells
    let mut term_cell_outputs: Vec<_> = terminal_cells
        .iter()
        .map(
            |ErgoTermCell {
                 ergs,
                 address,
                 tokens,
             }| {
                let tokens = if tokens.is_empty() {
                    None
                } else {
                    Some(BoxTokens::from_vec(tokens.clone()).unwrap())
                };
                ErgoBoxCandidate {
                    value: *ergs,
                    ergo_tree: address.script().unwrap(),
                    tokens,
                    additional_registers: NonMandatoryRegisters::empty(),
                    creation_height: current_height,
                }
            },
        )
        .collect();

    let initial_vault_balance = vault_utxo.value.as_i64();
    let ergs_to_distribute: i64 = terminal_cells.iter().map(|t| t.ergs.as_i64()).sum();

    let mut values = IndexMap::new();
    values.insert(0, exclusion_set_data);
    values.insert(5, aggregate_response);
    values.insert(1, serialized_aggregate_commitment);
    values.insert(6, Constant::from(md.as_ref().to_vec()));
    values.insert(9, threshold.into());
    values.insert(2, ErgoTermCells(terminal_cells).into());
    values.insert(7, avl_const);
    values.insert(3, proof);
    values.insert(8, change_for_miner.as_i64().into());

    let vault_output_box = ErgoBoxCandidate {
        value: BoxValue::try_from(initial_vault_balance - change_for_miner.as_i64() - ergs_to_distribute)
            .unwrap(),
        ergo_tree: VAULT_CONTRACT.clone(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height: current_height,
    };

    let miner_output = ErgoBoxCandidate {
        value: change_for_miner,
        ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height: current_height,
    };
    term_cell_outputs.push(vault_output_box);
    term_cell_outputs.push(miner_output);
    let outputs = TxIoVec::from_vec(term_cell_outputs).unwrap();
    let unsigned_input = UnsignedInput::new(vault_utxo.box_id(), ContextExtension { values });

    let data_inputs: Vec<_> = data_boxes
        .iter()
        .map(|d| DataInput { box_id: d.box_id() })
        .collect();
    let data_inputs = Some(TxIoVec::from_vec(data_inputs).unwrap());

    let unsigned_tx = UnsignedTransaction::new(
        TxIoVec::from_vec(vec![unsigned_input]).unwrap(),
        data_inputs,
        outputs,
    )
    .unwrap();
    let tx_context = TransactionContext::new(unsigned_tx, vec![vault_utxo], data_boxes).unwrap();
    let now = Instant::now();
    println!("Signing TX...");
    let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
    if res.is_err() {
        panic!("{:?}", res);
    }
    println!("Time to validate and sign: {} ms", now.elapsed().as_millis());
    res.unwrap()
}

const KEY_LENGTH: usize = 8;
const VALUE_LENGTH: usize = 32;
const MIN_KEY: [u8; KEY_LENGTH] = [0u8; KEY_LENGTH];
const MAX_KEY: [u8; KEY_LENGTH] = [0xFFu8; KEY_LENGTH];
