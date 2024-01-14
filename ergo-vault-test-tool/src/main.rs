use std::{collections::HashMap, mem::swap};

use clap::{arg, command, Parser, Subcommand};
use ergo_chain_sync::client::{
    node::{ErgoNetwork as _, ErgoNodeHttpClient},
    types::{InvalidUrl, Url},
};
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::chain::transaction::UnsignedInput;
use ergo_lib::wallet::signing::TransactionContext;
use ergo_lib::{
    chain::{ergo_box::box_builder::ErgoBoxCandidateBuilder, transaction::TxIoVec},
    ergo_chain_types::EcPoint,
    ergotree_interpreter::sigma_protocol::prover::ContextExtension,
    ergotree_ir::{
        chain::{
            address::{Address, AddressEncoder, NetworkPrefix},
            ergo_box::{
                box_value::BoxValue, BoxId, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
            },
            token::{Token, TokenAmount, TokenId},
        },
        ergo_tree::ErgoTree,
        mir::{
            constant::{Constant, Literal},
            value::CollKind,
        },
        serialization::SigmaSerializable,
        types::stype::SType,
    },
    wallet::box_selector::{BoxSelector, SimpleBoxSelector},
};
use indexmap::IndexMap;
use isahc::{config::Configurable, HttpClient};
use itertools::Itertools;
use k256::{elliptic_curve::group::GroupEncoding, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::ProtoTermCell;
use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_deploy_lm_pool::Explorer;
use spectrum_ergo_connector::{
    committee::{FirstCommitteeBox, SubsequentCommitteeBox, VaultParameters},
    script::{
        simulate_signature_aggregation_notarized_proofs, ErgoTermCell, DEPOSIT_CONTRACT, VAULT_CONTRACT,
    },
};
use spectrum_handel::Threshold;
use spectrum_ledger::{
    cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, PolicyId, SValue},
    ChainId,
};
use spectrum_move::SerializedValue;
use spectrum_offchain::{
    event_sink::handlers::types::IntoBoxCandidate, network::ErgoNetwork, transaction::TransactionCandidate,
};
use spectrum_offchain_lm::{
    data::miner::MinerOutput,
    ergo::{NanoErg, DEFAULT_MINER_FEE, MIN_SAFE_BOX_VALUE},
    prover::{SeedPhrase, SigmaProver, Wallet},
};
use tokio::{fs::File, io::AsyncWriteExt};

#[tokio::main]
async fn main() {
    let args = AppArgs::parse();
    match args.command {
        Command::CreateCommitteeBoxes { config_path } => {
            let raw_config = tokio::fs::read_to_string(config_path.clone())
                .await
                .expect("Cannot load configuration file");
            let config_proto: AppConfigProto =
                serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
            let mut config = AppConfig::try_from(config_proto).unwrap();
            create_committee_boxes(&mut config).await;

            tokio::fs::write(
                config_path,
                serde_yaml::to_string(&AppConfigProto::from(config)).unwrap(),
            )
            .await
            .unwrap();
        }

        Command::CreateVaultUtxo {
            config_path,
            nano_ergs,
            minted_token_name,
            minted_token_description,
        } => {
            let raw_config = tokio::fs::read_to_string(config_path.clone())
                .await
                .expect("Cannot load configuration file");
            let config_proto: AppConfigProto =
                serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
            let config = AppConfig::try_from(config_proto).unwrap();
            let vault_config = create_vault_utxo(
                NanoErg::from(nano_ergs),
                minted_token_name,
                minted_token_description,
                config,
            )
            .await;
            tokio::fs::write(
                config_path,
                serde_yaml::to_string(&AppConfigWithVaultUtxoProto::from(vault_config)).unwrap(),
            )
            .await
            .unwrap();
        }

        Command::GenerateCommittee {
            committee_size,
            output_file_name,
        } => {
            let mut rng = OsRng;
            let mut committee_public_keys = vec![];
            let mut committee_secret_keys = vec![];
            for _ in 0..committee_size {
                let sk = SecretKey::random(&mut rng);
                committee_public_keys.push(sk.public_key());
                committee_secret_keys.push(sk);
            }
            let config = AppConfig {
                node_addr: Url::try_from(String::from("http://213.239.193.208:9053")).unwrap(),
                http_client_timeout_duration_secs: 30,
                operator_funding_secret: SeedPhrase::from(String::from("add seed phrase here")),
                committee_public_keys,
                committee_secret_keys,
                committee_box_ids: None,
                box_ids_to_ignore: None,
            };
            let yaml_str = serde_yaml::to_string(&AppConfigProto::from(config)).unwrap();
            let mut file = File::create(output_file_name).await.unwrap();

            // Write the data to the file
            file.write_all(yaml_str.as_bytes()).await.unwrap();
        }

        Command::MakeWithdrawalTx {
            max_miner_fee,
            config_path,
        } => {
            let raw_config = tokio::fs::read_to_string(config_path.clone())
                .await
                .expect("Cannot load configuration file");
            let config_proto: AppConfigWithVaultUtxoProto =
                serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
            let mut config = AppConfigWithVaultUtxo::try_from(config_proto).unwrap();
            make_vault_withdrawal_tx(max_miner_fee, &mut config).await;
            let yaml_str = serde_yaml::to_string(&AppConfigWithVaultUtxoProto::from(config)).unwrap();
            let mut file = File::create(config_path).await.unwrap();

            // Write the data to the file
            file.write_all(yaml_str.as_bytes()).await.unwrap();
        }

        Command::MakeDeposit {
            nano_ergs,
            config_path,
        } => {
            let raw_config = tokio::fs::read_to_string(config_path.clone())
                .await
                .expect("Cannot load configuration file");
            let config_proto: AppConfigWithVaultUtxoProto =
                serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
            let mut config = AppConfigWithVaultUtxo::try_from(config_proto).unwrap();
            make_deposit_tx(NanoErg::from(nano_ergs), &mut config).await;
        }

        Command::RefundDeposit { box_id, config_path } => {
            let raw_config = tokio::fs::read_to_string(config_path.clone())
                .await
                .expect("Cannot load configuration file");
            let config_proto: AppConfigWithVaultUtxoProto =
                serde_yaml::from_str(&raw_config).expect("Invalid configuration file");
            let mut config = AppConfigWithVaultUtxo::try_from(config_proto).unwrap();

            let box_id = BoxId::try_from(box_id).unwrap();

            make_refund_deposit_tx(box_id, &mut config).await;
        }
    }
}

async fn create_committee_boxes(config: &mut AppConfig) {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(50))
        .build()
        .unwrap();

    let node_url = config.node_addr.clone();
    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };
    let node = ErgoNodeHttpClient::new(client, node_url);

    let current_height = node.get_height().await as i32;

    let vault_parameters = VaultParameters {
        num_committee_boxes: 0, // dummy value for now.
        current_epoch: 1,
        epoch_length: 100000,
        vault_starting_height: current_height - 100,
    };

    let committee_bytes = config
        .committee_public_keys
        .iter()
        .fold(Vec::<u8>::new(), |mut b, pk| {
            b.extend_from_slice(pk.to_projective().to_bytes().as_slice());
            b
        });
    let committee_hash = blake2b256_hash(&committee_bytes);

    // The first committee box can hold 115 public keys together with other data necessary to
    // verify signatures.
    const NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX: usize = 115;

    // We've determined empirically that we can fit at most 118 public keys into a single box.
    const MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX: usize = 118;

    let mut pk_keys_iter = config.committee_public_keys.clone().into_iter();
    let keys_first_box: Vec<_> = pk_keys_iter
        .by_ref()
        .take(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX)
        .map(|pk| EcPoint::from(pk.to_projective()))
        .collect();

    let mut seed = SeedPhrase::from(String::from(""));
    swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    seed = SeedPhrase::from(secret_str.clone());
    config.operator_funding_secret = SeedPhrase::from(secret_str);
    let (wallet, wallet_addr) = Wallet::try_from_seed(seed).expect("Invalid wallet seed");

    let guarding_script = wallet_addr.script().unwrap();

    let mut first_box = FirstCommitteeBox {
        public_keys: keys_first_box,
        vault_parameters,
        committee_hash,
        guarding_script: guarding_script.clone(),
        box_value: BoxValue::from(MIN_SAFE_BOX_VALUE),
    };

    let mut total_nergs_needed = 0_u64;

    let subsequent_committee_boxes: Vec<_> = pk_keys_iter
        .chunks(MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX)
        .into_iter()
        .enumerate()
        .map(|(ix, chunk)| {
            let public_keys = chunk.map(|pk| EcPoint::from(pk.to_projective())).collect();
            let mut bx = SubsequentCommitteeBox {
                public_keys,
                index: (ix as u32) + 1,
                guarding_script: guarding_script.clone(),
                box_value: BoxValue::from(MIN_SAFE_BOX_VALUE),
            }
            .into_candidate(current_height as u32);
            let box_bytes = bx.sigma_serialize_bytes().unwrap().len() as u64;
            let nergs = (box_bytes + 34) * ((BoxValue::MIN_VALUE_PER_BOX_BYTE) as u64);
            println!("nergs needed: {}", nergs);
            total_nergs_needed += nergs;
            bx.value = BoxValue::try_from(nergs).unwrap();
            bx
        })
        .collect();

    first_box.vault_parameters.num_committee_boxes = (subsequent_committee_boxes.len() + 1) as i32;

    let mut first_box = first_box.into_candidate(current_height as u32);

    let first_box_bytes = first_box.sigma_serialize_bytes().unwrap().len() as u64;
    let nergs = (first_box_bytes + 34) * ((BoxValue::MIN_VALUE_PER_BOX_BYTE) as u64);
    println!("nergs needed: {}", nergs);
    total_nergs_needed += nergs;
    first_box.value = BoxValue::try_from(nergs).unwrap();

    let mut output_candidates: Vec<_> = std::iter::once(first_box)
        .chain(subsequent_committee_boxes)
        .collect();

    // Now select input boxes
    let utxos = explorer
        .get_utxos(&wallet_addr)
        .await
        .unwrap()
        .into_iter()
        .filter(|bx| {
            if let Some(to_ignore) = &config.box_ids_to_ignore {
                !to_ignore.contains(&bx.box_id())
            } else {
                true
            }
        })
        .collect();
    let target_balance = BoxValue::try_from(total_nergs_needed).unwrap();
    let mut miner_output = MinerOutput {
        erg_value: DEFAULT_MINER_FEE,
    };
    let accumulated_cost = miner_output.erg_value + NanoErg::from(target_balance);
    let selection_value = BoxValue::try_from(accumulated_cost).unwrap();
    let box_selector = SimpleBoxSelector::new();

    let box_selection = box_selector.select(utxos, selection_value, &[]).unwrap();
    let funds_total = box_selection.boxes.iter().fold(NanoErg::from(0), |acc, ergobox| {
        acc + NanoErg::from(ergobox.value)
    });
    let funds_remain = funds_total.safe_sub(accumulated_cost);
    if funds_remain >= MIN_SAFE_BOX_VALUE {
        let builder = ErgoBoxCandidateBuilder::new(
            BoxValue::from(funds_remain),
            guarding_script,
            current_height as u32,
        );
        output_candidates.push(builder.build().unwrap());
    } else {
        miner_output.erg_value = miner_output.erg_value + funds_remain;
    }
    output_candidates.push(miner_output.into_candidate(current_height as u32));
    let inputs = TxIoVec::from_vec(
        box_selection
            .boxes
            .clone()
            .into_iter()
            .map(|bx| (bx, ContextExtension::empty()))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let num_outputs = output_candidates.len();

    let tx_candidate = TransactionCandidate {
        inputs,
        data_inputs: None,
        output_candidates: TxIoVec::from_vec(output_candidates).unwrap(),
    };
    let signed_tx = wallet.sign(tx_candidate).unwrap();
    //dbg!(&signed_tx);

    // Store box ids of new committee boxes
    let committee_box_ids: Vec<_> = signed_tx
        .outputs
        .iter()
        .take(num_outputs - 2)
        .map(|bx| bx.box_id())
        .collect();
    config.committee_box_ids = Some(committee_box_ids);

    let tx_id = signed_tx.id();
    if let Err(e) = node.submit_tx(signed_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("TX {:?} successfully submitted!", tx_id);
    }
}

async fn create_vault_utxo(
    amt: NanoErg,
    token_name: String,
    token_desc: String,
    mut config: AppConfig,
) -> AppConfigWithVaultUtxo {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(50))
        .build()
        .unwrap();

    let node_url = Url::try_from(String::from("http://213.239.193.208:9053")).unwrap();
    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };
    let node = ErgoNodeHttpClient::new(client, node_url);

    let mut seed = SeedPhrase::from(String::from(""));
    swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    seed = SeedPhrase::from(secret_str.clone());
    config.operator_funding_secret = SeedPhrase::from(secret_str);
    let (wallet, wallet_addr) = Wallet::try_from_seed(seed).expect("Invalid wallet seed");

    let mut box_ids_to_ignore = if let Some(to_ignore) = &config.committee_box_ids {
        to_ignore.clone()
    } else {
        vec![]
    };
    if let Some(to_ignore) = &config.box_ids_to_ignore {
        box_ids_to_ignore.extend(to_ignore);
    }
    // Need to make sure we don't spent the committee box
    let utxos = explorer
        .get_utxos(&wallet_addr)
        .await
        .unwrap()
        .into_iter()
        .filter(|bx| !box_ids_to_ignore.contains(&bx.box_id()))
        .collect();
    let height = node.get_height().await;

    // To mint the initial Vault UTxO, we will require a chain TX with 2 legs:
    //  1. First need a TX to mint the vault tokens (requires MIN_SAFE_BOX_VALUE + DEFAULT_MINER_FEE)
    //  2. Create the initial Vault UTxO (requires another `amt - MIN_SAFE_BOX_VALUE + DEFAULT_MINER_FEE`,
    //     since we will spend the box holding the tokens in the first tx).
    let selection_value = BoxValue::from(amt + DEFAULT_MINER_FEE + DEFAULT_MINER_FEE);
    let box_selector = SimpleBoxSelector::new();
    let box_selection = box_selector.select(utxos, selection_value, &[]).unwrap();
    let box_selection_total_value = BoxValue::try_from(
        box_selection
            .boxes
            .iter()
            .fold(0_u64, |acc, bx| acc + bx.value.as_u64()),
    )
    .unwrap();
    let minted_token = Token {
        token_id: box_selection.boxes.first().box_id().into(),
        amount: TokenAmount::try_from(TokenAmount::MAX_RAW).unwrap(),
    };
    let guarding_script = wallet_addr.script().unwrap();
    let mut builder = ErgoBoxCandidateBuilder::new(
        BoxValue::from(MIN_SAFE_BOX_VALUE),
        guarding_script.clone(),
        height,
    );
    builder.mint_token(minted_token.clone(), token_name, token_desc, 0);
    let mut output_candidates = vec![builder.build().unwrap()];

    let miner_output = MinerOutput {
        erg_value: DEFAULT_MINER_FEE,
    };

    let funds_for_next_tx = ErgoBoxCandidateBuilder::new(
        BoxValue::from(amt + DEFAULT_MINER_FEE - MIN_SAFE_BOX_VALUE),
        guarding_script.clone(),
        height,
    )
    .build()
    .unwrap();

    let remaining_funds = ErgoBoxCandidateBuilder::new(
        box_selection_total_value.checked_sub(&selection_value).unwrap(),
        guarding_script.clone(),
        height,
    )
    .build()
    .unwrap();

    output_candidates.extend(vec![
        funds_for_next_tx,
        remaining_funds,
        miner_output.clone().into_candidate(height),
    ]);

    let inputs = TxIoVec::from_vec(
        box_selection
            .boxes
            .into_iter()
            .map(|bx| (bx, ContextExtension::empty()))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let output_candidates = TxIoVec::from_vec(output_candidates.clone()).unwrap();
    let tx_candidate = TransactionCandidate {
        inputs,
        data_inputs: None,
        output_candidates,
    };
    let signed_token_minting_tx = wallet.sign(tx_candidate).unwrap();
    let tx_id = signed_token_minting_tx.id();

    let inputs: Vec<_> = signed_token_minting_tx
        .outputs
        .clone()
        .into_iter()
        .take(2)
        .collect();

    if let Err(e) = node.submit_tx(signed_token_minting_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("Token minting TX {:?} successfully submitted!", tx_id);
    }

    // Vault UTxO.
    let mut builder = ErgoBoxCandidateBuilder::new(BoxValue::from(amt), VAULT_CONTRACT.clone(), height);
    builder.add_token(minted_token.clone());
    let mut vault_output_box = builder.build().unwrap();

    let items: Vec<_> = config
        .committee_box_ids
        .as_ref()
        .unwrap()
        .iter()
        .map(|input| Literal::from(input.sigma_serialize_bytes().unwrap()))
        .collect();

    let serialized_committee_box_ids = Constant {
        tpe: SType::SColl(Box::new(SType::SColl(Box::new(SType::SByte)))),
        v: Literal::Coll(CollKind::WrappedColl {
            elem_tpe: SType::SColl(Box::new(SType::SByte)),
            items,
        }),
    };

    let mut registers = HashMap::new();
    registers.insert(NonMandatoryRegisterId::R4, serialized_committee_box_ids);
    vault_output_box.additional_registers = NonMandatoryRegisters::new(registers).unwrap();
    let mut output_candidates = vec![vault_output_box];

    output_candidates.push(miner_output.into_candidate(height));

    let inputs = TxIoVec::from_vec(
        inputs
            .into_iter()
            .map(|bx| (bx, ContextExtension::empty()))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let tx_candidate = TransactionCandidate {
        inputs,
        data_inputs: None,
        output_candidates: TxIoVec::from_vec(output_candidates).unwrap(),
    };
    let signed_tx = wallet.sign(tx_candidate).unwrap();
    //dbg!(&signed_tx);

    let tx_id = signed_tx.id();
    let new_vault_utxo_box_id = signed_tx.outputs.get(0).unwrap().box_id();
    if let Err(e) = node.submit_tx(signed_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("Vault UTxO creation TX {:?} successfully submitted!", tx_id);
    }
    AppConfigWithVaultUtxo {
        node_addr: config.node_addr,
        http_client_timeout_duration_secs: config.http_client_timeout_duration_secs,
        operator_funding_secret: config.operator_funding_secret,
        committee_public_keys: config.committee_public_keys,
        committee_secret_keys: config.committee_secret_keys,
        committee_box_ids: config.committee_box_ids,
        box_ids_to_ignore: config.box_ids_to_ignore,
        spent_vault_utxo_box_id: None,
        new_vault_utxo_box_id,
        vault_utxo_token_id: minted_token.token_id,
    }
}

async fn make_vault_withdrawal_tx(max_miner_fee: i64, config: &mut AppConfigWithVaultUtxo) {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(50))
        .build()
        .unwrap();

    let node_url = config.node_addr.clone();
    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };
    let node = ErgoNodeHttpClient::new(client, node_url);

    let vault_utxo_box_id = config.new_vault_utxo_box_id;

    let mut data_boxes = vec![];
    if let Some(committee_box_ids) = &config.committee_box_ids {
        for box_id in committee_box_ids {
            let bx = explorer.get_box(*box_id).await.unwrap();
            data_boxes.push(bx);
        }
    }
    let vault_utxo = explorer.get_box(vault_utxo_box_id).await.unwrap();
    let ergo_state_context = node.get_ergo_state_context().await.unwrap();

    let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
    let addr_0 = encoder
        .parse_address_from_str("9hVmDmyrLoNAupFVoobZRCfbwDWnAvCmjT1KCS4yGy3XziaCyMg")
        .unwrap();

    let size = 466160; //46869640; //(383979280 - 2_000_000 - 250000) / 2;
    let term_cells = vec![proto_term_cell(size, vec![], addr_0.content_bytes())]
        .into_iter()
        .map(|cell| ErgoTermCell::try_from(cell).unwrap())
        .collect();

    let inputs = simulate_signature_aggregation_notarized_proofs(
        config.committee_secret_keys.clone(),
        term_cells,
        0,
        Threshold { num: 3, denom: 3 },
        max_miner_fee,
    );

    let mut seed = SeedPhrase::from(String::from(""));
    swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    seed = SeedPhrase::from(secret_str.clone());
    config.operator_funding_secret = seed;
    let wallet = ergo_lib::wallet::Wallet::from_mnemonic(&secret_str, "").unwrap();

    let signed_tx = spectrum_ergo_connector::vault::verify_vault_contract_ergoscript_with_sigma_rust(
        inputs,
        config.committee_public_keys.len() as u32,
        ergo_state_context,
        vault_utxo,
        config.vault_utxo_token_id,
        data_boxes,
        &wallet,
        node.get_height().await,
    );
    let num_outputs = signed_tx.outputs.len();
    config.spent_vault_utxo_box_id = Some(vault_utxo_box_id);
    config.new_vault_utxo_box_id = signed_tx.outputs.get(0).unwrap().box_id();

    let tx_id = signed_tx.id();
    if let Err(e) = node.submit_tx(signed_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("TX {:?} successfully submitted!", tx_id);
    }
}

async fn make_deposit_tx(deposit_amt: NanoErg, config: &mut AppConfigWithVaultUtxo) {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(50))
        .build()
        .unwrap();

    let node_url = config.node_addr.clone();
    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };
    let node = ErgoNodeHttpClient::new(client, node_url);

    let mut seed = SeedPhrase::from(String::from(""));
    swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    seed = SeedPhrase::from(secret_str.clone());
    config.operator_funding_secret = SeedPhrase::from(secret_str);
    let (wallet, wallet_addr) = Wallet::try_from_seed(seed).expect("Invalid wallet seed");
    let guarding_script = wallet_addr.script().unwrap();
    let Address::P2Pk(prove_dlog) = wallet_addr.clone() else {
        panic!("EXPECT P2PK ADDRESS FOR WALLET");
    };

    let mut box_ids_to_ignore = if let Some(to_ignore) = &config.committee_box_ids {
        to_ignore.clone()
    } else {
        vec![]
    };
    if let Some(to_ignore) = &config.box_ids_to_ignore {
        box_ids_to_ignore.extend(to_ignore);
    }
    // Need to make sure we don't spent the committee box
    let utxos = explorer
        .get_utxos(&wallet_addr)
        .await
        .unwrap()
        .into_iter()
        .filter(|bx| !box_ids_to_ignore.contains(&bx.box_id()))
        .collect();
    let current_height = node.get_height().await;
    let mut miner_output = MinerOutput {
        erg_value: DEFAULT_MINER_FEE,
    };
    let selection_value = BoxValue::from(deposit_amt + DEFAULT_MINER_FEE);

    let mut registers = HashMap::new();
    registers.insert(
        NonMandatoryRegisterId::R4,
        Constant::from(config.vault_utxo_token_id),
    );
    registers.insert(NonMandatoryRegisterId::R5, Constant::from(prove_dlog));
    let deposit_box = ErgoBoxCandidate {
        value: BoxValue::from(deposit_amt),
        ergo_tree: DEPOSIT_CONTRACT.clone(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::new(registers).unwrap(),
        creation_height: current_height,
    };

    let mut output_candidates = vec![deposit_box];

    let box_selector = SimpleBoxSelector::new();
    let box_selection = box_selector.select(utxos, selection_value, &[]).unwrap();
    let funds_total = box_selection.boxes.iter().fold(NanoErg::from(0), |acc, ergobox| {
        acc + NanoErg::from(ergobox.value)
    });
    let funds_remain = funds_total.safe_sub(NanoErg::from(selection_value));
    if funds_remain >= MIN_SAFE_BOX_VALUE {
        let builder = ErgoBoxCandidateBuilder::new(
            BoxValue::from(funds_remain),
            guarding_script,
            current_height as u32,
        );
        output_candidates.push(builder.build().unwrap());
    } else {
        miner_output.erg_value = miner_output.erg_value + funds_remain;
    }
    output_candidates.push(miner_output.into_candidate(current_height as u32));

    let inputs = TxIoVec::from_vec(
        box_selection
            .boxes
            .clone()
            .into_iter()
            .map(|bx| (bx, ContextExtension::empty()))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    let tx_candidate = TransactionCandidate {
        inputs,
        data_inputs: None,
        output_candidates: TxIoVec::from_vec(output_candidates).unwrap(),
    };
    let signed_tx = wallet.sign(tx_candidate).unwrap();
    let tx_id = signed_tx.id();
    if let Err(e) = node.submit_tx(signed_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("DEPOSIT TX {:?} successfully submitted!", tx_id);
    }
}

async fn make_refund_deposit_tx(deposit_box_id: BoxId, config: &mut AppConfigWithVaultUtxo) {
    let client = HttpClient::builder()
        .timeout(std::time::Duration::from_secs(50))
        .build()
        .unwrap();

    let explorer_url = Url::try_from(String::from("https://api.ergoplatform.com")).unwrap();
    let explorer = Explorer {
        client: client.clone(),
        base_url: explorer_url,
    };

    let deposit_box = explorer.get_box(deposit_box_id).await.unwrap();
    let deposit_amt = NanoErg::from(deposit_box.value);
    if deposit_amt <= DEFAULT_MINER_FEE {
        panic!("Deposit value is smaller than miner fee. Shouldn't happen");
    }

    let node_url = config.node_addr.clone();
    let node = ErgoNodeHttpClient::new(client, node_url);

    let mut seed = SeedPhrase::from(String::from(""));
    swap(&mut config.operator_funding_secret, &mut seed);
    let secret_str = String::from(seed);
    seed = SeedPhrase::from(secret_str.clone());
    config.operator_funding_secret = SeedPhrase::from(secret_str.clone());
    let (wallet, wallet_addr) = Wallet::try_from_seed(seed).expect("Invalid wallet seed");
    let guarding_script = wallet_addr.script().unwrap();
    println!("WALLET ADDR: {:?}", wallet_addr);
    let Address::P2Pk(prove_dlog) = wallet_addr.clone() else {
        panic!("EXPECT P2PK ADDRESS FOR WALLET");
    };

    let current_height = node.get_height().await;
    let mut miner_output = MinerOutput {
        erg_value: DEFAULT_MINER_FEE,
    };

    let refund_output_box = ErgoBoxCandidate {
        value: BoxValue::try_from(deposit_amt - DEFAULT_MINER_FEE).unwrap(),
        ergo_tree: guarding_script,
        tokens: deposit_box.tokens.clone(),
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height: current_height,
    };
    let mut constants = IndexMap::new();
    constants.insert(8_u8, Constant::from(BoxValue::from(DEFAULT_MINER_FEE)));
    let inputs = TxIoVec::from_vec(vec![
        (UnsignedInput::new(deposit_box.box_id(), ContextExtension { values: constants })),
    ])
    .unwrap();
    //deposit_box.clone(),
    let output_candidates = TxIoVec::from_vec(vec![
        refund_output_box,
        miner_output.into_candidate(current_height),
    ])
    .unwrap();
    let unsigned_tx = UnsignedTransaction::new(inputs, None, output_candidates).unwrap();
    let tx_context = TransactionContext::new(unsigned_tx, vec![deposit_box], vec![]).unwrap();

    // Need Wallet instance from ergo-lib
    let ergo_wallet = ergo_lib::wallet::Wallet::from_mnemonic(&secret_str, "").unwrap();
    let ergo_state_context = node.get_ergo_state_context().await.unwrap();
    let signed_tx = ergo_wallet
        .sign_transaction(tx_context, &ergo_state_context, None)
        .unwrap();
    let tx_id = signed_tx.id();
    if let Err(e) = node.submit_tx(signed_tx).await {
        println!("ERGO NODE ERROR: {:?}", e);
    } else {
        println!("REFUND TX {:?} successfully submitted!", tx_id);
    }
}

pub fn proto_term_cell(nano_ergs: u64, tokens: Vec<Token>, address_bytes: Vec<u8>) -> ProtoTermCell {
    let dst = BoxDestination {
        target: ChainId::from(0),
        address: SerializedValue::from(address_bytes),
        inputs: None,
    };
    let mut assets = HashMap::new();
    let asset_map: HashMap<AssetId, CustomAsset> = tokens
        .into_iter()
        .map(|t| {
            let from = AssetId::from(Blake2bDigest256::try_from(<Vec<u8>>::from(t.token_id)).unwrap());
            let asset_id = from;
            let custom_asset = CustomAsset::from(*t.amount.as_u64());
            (asset_id, custom_asset)
        })
        .collect();
    assets.insert(PolicyId::from(Blake2bDigest256::zero()), asset_map);
    ProtoTermCell {
        value: SValue {
            native: NativeCoin::from(nano_ergs),
            assets,
        },
        dst,
    }
}

struct AppConfigWithVaultUtxo {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    operator_funding_secret: SeedPhrase,
    committee_public_keys: Vec<PublicKey>,
    committee_secret_keys: Vec<SecretKey>,
    committee_box_ids: Option<Vec<BoxId>>,
    box_ids_to_ignore: Option<Vec<BoxId>>,
    spent_vault_utxo_box_id: Option<BoxId>,
    new_vault_utxo_box_id: BoxId,
    vault_utxo_token_id: TokenId,
}

#[derive(Deserialize, Serialize)]
struct AppConfigWithVaultUtxoProto {
    node_addr: String,
    http_client_timeout_duration_secs: u32,
    operator_funding_secret: String,
    committee_public_keys: Vec<String>,
    committee_secret_keys: Vec<String>,
    committee_box_ids: Option<Vec<BoxId>>,
    box_ids_to_ignore: Option<Vec<BoxId>>,
    spent_vault_utxo_box_id: Option<BoxId>,
    new_vault_utxo_box_id: BoxId,
    vault_utxo_token_id: TokenId,
}

struct AppConfig {
    node_addr: Url,
    http_client_timeout_duration_secs: u32,
    operator_funding_secret: SeedPhrase,
    committee_public_keys: Vec<PublicKey>,
    committee_secret_keys: Vec<SecretKey>,
    committee_box_ids: Option<Vec<BoxId>>,
    box_ids_to_ignore: Option<Vec<BoxId>>,
}

#[derive(Deserialize, Serialize)]
struct AppConfigProto {
    node_addr: String,
    http_client_timeout_duration_secs: u32,
    operator_funding_secret: String,
    committee_public_keys: Vec<String>,
    committee_secret_keys: Vec<String>,
    committee_box_ids: Option<Vec<BoxId>>,
    box_ids_to_ignore: Option<Vec<BoxId>>,
}

#[derive(Debug, derive_more::From)]
enum Error {
    Url(InvalidUrl),
}

impl TryFrom<AppConfigProto> for AppConfig {
    type Error = Error;

    fn try_from(value: AppConfigProto) -> Result<Self, Self::Error> {
        let node_addr = Url::try_from(value.node_addr)?;
        let operator_funding_secret = SeedPhrase::from(value.operator_funding_secret);
        let committee_public_keys = value
            .committee_public_keys
            .into_iter()
            .map(|pk_str| {
                let bytes = base16::decode(&pk_str).unwrap();
                PublicKey::from_sec1_bytes(&bytes).unwrap()
            })
            .collect();
        let committee_secret_keys = value
            .committee_secret_keys
            .into_iter()
            .map(|sk_str| {
                let bytes = base16::decode(&sk_str).unwrap();
                SecretKey::from_slice(&bytes).unwrap()
            })
            .collect();
        Ok(AppConfig {
            node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            operator_funding_secret,
            committee_public_keys,
            committee_secret_keys,
            committee_box_ids: value.committee_box_ids,
            box_ids_to_ignore: value.box_ids_to_ignore,
        })
    }
}

impl From<AppConfig> for AppConfigProto {
    fn from(value: AppConfig) -> Self {
        let node_addr = value.node_addr.to_string();
        let operator_funding_secret = String::from(value.operator_funding_secret);
        let committee_public_keys = value
            .committee_public_keys
            .into_iter()
            .map(|pk| {
                let bytes = pk.to_sec1_bytes().as_ref().to_vec();
                base16::encode_lower(&bytes)
            })
            .collect();
        let committee_secret_keys = value
            .committee_secret_keys
            .into_iter()
            .map(|sk| base16::encode_lower(sk.to_bytes().as_slice()))
            .collect();
        Self {
            node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            operator_funding_secret,
            committee_public_keys,
            committee_secret_keys,
            committee_box_ids: value.committee_box_ids,
            box_ids_to_ignore: value.box_ids_to_ignore,
        }
    }
}

impl TryFrom<AppConfigWithVaultUtxoProto> for AppConfigWithVaultUtxo {
    type Error = Error;

    fn try_from(value: AppConfigWithVaultUtxoProto) -> Result<Self, Self::Error> {
        let config_proto = AppConfigProto {
            node_addr: value.node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            operator_funding_secret: value.operator_funding_secret,
            committee_public_keys: value.committee_public_keys,
            committee_secret_keys: value.committee_secret_keys,
            committee_box_ids: value.committee_box_ids,
            box_ids_to_ignore: value.box_ids_to_ignore,
        };

        let config = AppConfig::try_from(config_proto)?;
        Ok(Self {
            node_addr: config.node_addr,
            http_client_timeout_duration_secs: config.http_client_timeout_duration_secs,
            operator_funding_secret: config.operator_funding_secret,
            committee_public_keys: config.committee_public_keys,
            committee_secret_keys: config.committee_secret_keys,
            committee_box_ids: config.committee_box_ids,
            box_ids_to_ignore: config.box_ids_to_ignore,
            spent_vault_utxo_box_id: value.spent_vault_utxo_box_id,
            new_vault_utxo_box_id: value.new_vault_utxo_box_id,
            vault_utxo_token_id: value.vault_utxo_token_id,
        })
    }
}

impl From<AppConfigWithVaultUtxo> for AppConfigWithVaultUtxoProto {
    fn from(value: AppConfigWithVaultUtxo) -> Self {
        let config = AppConfig {
            node_addr: value.node_addr,
            http_client_timeout_duration_secs: value.http_client_timeout_duration_secs,
            operator_funding_secret: value.operator_funding_secret,
            committee_public_keys: value.committee_public_keys,
            committee_secret_keys: value.committee_secret_keys,
            committee_box_ids: value.committee_box_ids,
            box_ids_to_ignore: value.box_ids_to_ignore,
        };

        let config_proto = AppConfigProto::from(config);
        Self {
            node_addr: config_proto.node_addr,
            http_client_timeout_duration_secs: config_proto.http_client_timeout_duration_secs,
            operator_funding_secret: config_proto.operator_funding_secret,
            committee_public_keys: config_proto.committee_public_keys,
            committee_secret_keys: config_proto.committee_secret_keys,
            committee_box_ids: config_proto.committee_box_ids,
            box_ids_to_ignore: config_proto.box_ids_to_ignore,
            spent_vault_utxo_box_id: value.spent_vault_utxo_box_id,
            new_vault_utxo_box_id: value.new_vault_utxo_box_id,
            vault_utxo_token_id: value.vault_utxo_token_id,
        }
    }
}

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Spectrum Finance Ergo Vault test tool", long_about = None)]
struct AppArgs {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    CreateCommitteeBoxes {
        #[arg(long, short)]
        /// Path to the YAML configuration file.
        config_path: String,
    },

    CreateVaultUtxo {
        #[arg(long)]
        /// Path to the YAML configuration file.
        config_path: String,
        #[arg(long)]
        /// Amount of nano-ergs to be put into Vault UTxO
        nano_ergs: u64,
        #[arg(long)]
        /// Name of the Vault UTxO token to be minted
        minted_token_name: String,
        #[arg(long)]
        /// Description of the Vault UTxO token to be minted
        minted_token_description: String,
    },

    GenerateCommittee {
        #[arg(long, short)]
        /// Number of committee members.
        committee_size: u32,
        #[arg(long, short)]
        /// Name of output YAML file.
        output_file_name: String,
    },

    MakeWithdrawalTx {
        #[arg(long, short)]
        max_miner_fee: i64,

        #[arg(long, short)]
        /// Path to the YAML configuration file.
        config_path: String,
    },

    MakeDeposit {
        #[arg(long, short)]
        /// Amount of nano-ergs to be deposited
        nano_ergs: u64,

        #[arg(long, short)]
        /// Path to the YAML configuration file.
        config_path: String,
    },

    RefundDeposit {
        #[arg(long, short)]
        /// Base58 encoding of the Box id of the deposit box
        box_id: String,
        #[arg(long, short)]
        /// Path to the YAML configuration file.
        config_path: String,
    },
}
