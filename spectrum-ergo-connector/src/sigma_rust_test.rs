#[cfg(test)]
mod test {
    use ergo_lib::{
        chain::{
            ergo_state_context::ErgoStateContext,
            transaction::{unsigned::UnsignedTransaction, TxId, TxIoVec, UnsignedInput},
        },
        ergo_chain_types::EcPoint,
        ergotree_interpreter::sigma_protocol::prover::ContextExtension,
        ergotree_ir::{
            chain::{
                address::{Address, AddressEncoder, NetworkPrefix},
                ergo_box::{
                    box_value::BoxValue, BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisters,
                },
                token::{Token, TokenId},
            },
            mir::{
                constant::{Constant, Literal},
                value::CollKind,
            },
            serialization::SigmaSerializable,
            types::{
                stuple::{STuple, TupleItems},
                stype::SType,
            },
        },
        wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext, Wallet},
    };
    use indexmap::IndexMap;
    use rand::{rngs::OsRng, Rng};
    use sigma_test_util::force_any_val;

    pub struct ErgoTermCell {
        ergs: BoxValue,
        address: Address,
        tokens: Vec<Token>,
    }

    pub struct ErgoTermCells(Vec<ErgoTermCell>);

    impl ErgoTermCell {
        fn get_stype() -> SType {
            SType::STuple(STuple {
                items: TupleItems::from_vec(vec![
                    SType::SLong,
                    SType::STuple(STuple {
                        items: TupleItems::from_vec(vec![
                            SType::SColl(Box::new(SType::SByte)),
                            SType::SColl(Box::new(SType::STuple(STuple {
                                items: TupleItems::from_vec(vec![
                                    SType::SColl(Box::new(SType::SByte)),
                                    SType::SLong,
                                ])
                                .unwrap(),
                            }))),
                        ])
                        .unwrap(),
                    }),
                ])
                .unwrap(),
            })
        }
    }

    impl From<ErgoTermCell> for Constant {
        fn from(cell: ErgoTermCell) -> Self {
            // The Constant is of the form (nanoErg, (propositionBytes, tokens)), with type
            //    (Long, (Coll[Byte], Coll[(Coll[Byte], Long)]))
            //
            let nano_ergs: Constant = cell.ergs.into();
            let prop_bytes: Constant = cell
                .address
                .script()
                .unwrap()
                .sigma_serialize_bytes()
                .unwrap()
                .into();
            let elem_tpe = ErgoTermCell::get_stype();
            let tokens: Vec<Literal> = cell
                .tokens
                .into_iter()
                .map(|t| {
                    let tup: Constant = (
                        Constant::from(t.token_id),
                        Constant::from(*t.amount.as_u64() as i64),
                    )
                        .into();
                    tup.v
                })
                .collect();
            let tokens = Constant {
                tpe: SType::SColl(Box::new(elem_tpe.clone())),
                v: Literal::Coll(CollKind::WrappedColl {
                    elem_tpe,
                    items: tokens,
                }),
            };
            let inner_tuple: Constant = (prop_bytes, tokens).into();
            (nano_ergs, inner_tuple).into()
        }
    }

    impl From<ErgoTermCells> for Constant {
        fn from(value: ErgoTermCells) -> Self {
            let lits: Vec<_> = value
                .0
                .into_iter()
                .map(|e| {
                    let c = Constant::from(e);
                    c.v
                })
                .collect();
            Constant {
                tpe: SType::SColl(Box::new(ErgoTermCell::get_stype())),
                v: Literal::Coll(CollKind::WrappedColl {
                    elem_tpe: ErgoTermCell::get_stype(),
                    items: lits,
                }),
            }
        }
    }

    #[test]
    fn test_sigma_rust_issue() {
        let num_notarized_txs = 1;

        let max_num_tokens = 50;
        let current_height = 900000;
        let mut rng = OsRng;

        let mut total_num_tokens = 0;
        let terminal_cells: Vec<_> = (0..num_notarized_txs)
            .map(|_| {
                let address = generate_address();
                let ergs = BoxValue::try_from(rng.gen_range(1_u64..=9000000000)).unwrap();
                let contains_tokens = rng.gen_bool(0.5);
                let tokens = if contains_tokens {
                    let num_tokens = rng.gen_range(0_usize..=10);
                    if total_num_tokens + num_tokens <= max_num_tokens {
                        total_num_tokens += num_tokens;
                        (0..num_tokens).map(|_| gen_random_token()).collect()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                ErgoTermCell {
                    ergs,
                    address,
                    tokens,
                }
            })
            .collect();

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
                        creation_height: current_height as u32,
                    }
                },
            )
            .collect();

        let change_for_miner = BoxValue::try_from(1000000_u64).unwrap();
        let initial_vault_balance = 2000000000_i64;
        let ergs_to_distribute: i64 = terminal_cells.iter().map(|t| t.ergs.as_i64()).sum();

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            //.parse_address_from_str("6aXkYWtkRtsoFvUAt1ULzfePuhy9F86kQ1yEZpENfBBQ6yZtTsU5njM6ZPJbtFJaE5akmLAmGXc9QEULiBUxGukmfBrcWh3gbaZftByNLh4KufyW6xL1L9iq4mXjBiGEw4LqeB9xEyoNeGBBwuJ8af17XT9Ru3o1jR")
            .parse_address_from_str("8kT2dAtEgAbvWeszHMYwSpwZGA11kUdXCvAZw8NLjxdp7qmH1F5Mpxhq7ExSQLAckXbS8rPW17uLiTT5BFz5g1k8c5Tfxxs7rKYCpWRVLjYJFK5a1HMbGfofhFt9kbwJS8A8Y7R774BHraeAbbLY1wt2g1wt3jkjLPMiEU6gAn8s4emFXmg7ryG1mrsGF89huoqJnhFnZJfyZrCCiYQj7v3HWd71564xTxzSsrgPndgECA36Wahmhbd72USy34An1p2nqiKTnMm1LLizZR9CRo")
            .unwrap();
        let ergo_tree = address.script().unwrap();

        let input_box = ErgoBox::new(
            BoxValue::try_from(initial_vault_balance + ergs_to_distribute).unwrap(),
            ergo_tree,
            None,
            NonMandatoryRegisters::empty(),
            (current_height as u32) - 10,
            TxId::zero(),
            0,
        )
        .unwrap();

        let vault_output_box = ErgoBoxCandidate {
            value: BoxValue::try_from(initial_vault_balance - change_for_miner.as_i64()).unwrap(),
            ergo_tree: generate_address().script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height as u32,
        };

        let miner_output = ErgoBoxCandidate {
            value: change_for_miner,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height as u32,
        };
        term_cell_outputs.push(vault_output_box);
        term_cell_outputs.push(miner_output);

        let mut values = IndexMap::new();
        values.insert(0, ErgoTermCells(terminal_cells).into());
        let outputs = TxIoVec::from_vec(term_cell_outputs).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });

        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(vec![unsigned_input]).unwrap(), None, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], vec![]).unwrap();
        let wallet = get_wallet();
        let ergo_state_context = force_any_val::<ErgoStateContext>();

        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
    }

    fn gen_random_token() -> Token {
        let mut token = force_any_val::<Token>();
        let mut digest = ergo_lib::ergo_chain_types::Digest32::zero();

        let mut rng = rand::thread_rng();
        rng.fill(&mut digest.0);
        token.token_id = TokenId::from(digest);
        token
    }

    fn generate_address() -> Address {
        let mut rng = OsRng;
        let sk = k256::SecretKey::random(&mut rng);
        let proj = k256::PublicKey::from(sk.public_key()).to_projective();
        Address::P2Pk(
            ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog::from(EcPoint::from(proj)),
        )
    }

    fn get_wallet() -> Wallet {
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed")
    }
}
