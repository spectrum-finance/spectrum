use naumachia::scripts::raw_script::BlueprintFile;
use naumachia::scripts::raw_validator_script::plutus_data::{Constr, PlutusData};
use naumachia::scripts::raw_validator_script::RawPlutusValidator;
use naumachia::scripts::{ScriptError, ScriptResult};

const BLUEPRINT: &str = include_str!("../aiken/vault/plutus.json");
const VALIDATOR_NAME: &str = "verify_spectrum_report.release_value";

pub struct PackedSparseMerkleProof {
    /// This Vec is contiguous. E.g. if it contains 4 nodes, then they represents nodes 0, 1, 2 and
    /// 3 in the Merkle tree (ordered left to right).
    pub leaf_nodes_to_verify: Vec<Vec<u8>>,
    /// Internal nodes that are necessary to complete the Merkle multi proof.
    pub needed_internal_nodes: Vec<InternalNode>,
    /// If the last leaf in `leaf_nodes_to_verify` is a left-child, then the Merkle proof requires
    /// the hashed value of the right peer leaf.
    pub right_peer_hash: Option<Vec<u8>>,
    /// The root hash value of the Merkle tree.
    pub root_hash: Vec<u8>,
}

//(spectrum_ledger::merkle_tree::PackedSparseMerkleProof);

pub struct InternalNode {
    level: i64,
    hash: Vec<u8>,
}

impl From<InternalNode> for PlutusData {
    fn from(value: InternalNode) -> Self {
        PlutusData::Constr(Constr {
            constr: 0,
            fields: vec![value.level.into(), value.hash.into()],
        })
    }
}

impl From<PackedSparseMerkleProof> for PlutusData {
    fn from(value: PackedSparseMerkleProof) -> Self {
        let PackedSparseMerkleProof {
            leaf_nodes_to_verify,
            needed_internal_nodes,
            right_peer_hash,
            root_hash,
        } = value;

        let leaf_nodes_pd: Vec<PlutusData> = leaf_nodes_to_verify
            .into_iter()
            .map(|leaf_bytes| leaf_bytes.into())
            .collect();
        let leaf_nodes_pd = PlutusData::Array(leaf_nodes_pd);
        let needed_internal_nodes: Vec<PlutusData> =
            needed_internal_nodes.into_iter().map(PlutusData::from).collect();
        let needed_internal_nodes = PlutusData::Array(needed_internal_nodes);
        let root_hash = PlutusData::from(root_hash);
        let right_peer_hash = PlutusData::from(right_peer_hash);
        PlutusData::Constr(Constr {
            constr: 0,
            fields: vec![leaf_nodes_pd, needed_internal_nodes, right_peer_hash, root_hash],
        })
    }
}

pub fn get_script() -> ScriptResult<RawPlutusValidator<Option<i64>, PackedSparseMerkleProof>> {
    let script_file: BlueprintFile =
        serde_json::from_str(BLUEPRINT).map_err(|e| ScriptError::FailedToConstruct(e.to_string()))?;
    let validator_blueprint =
        script_file
            .get_validator(VALIDATOR_NAME)
            .ok_or(ScriptError::FailedToConstruct(format!(
                "Validator not listed in Blueprint: {:?}",
                VALIDATOR_NAME
            )))?;
    let raw_script_validator = RawPlutusValidator::from_blueprint(validator_blueprint)
        .map_err(|e| ScriptError::FailedToConstruct(e.to_string()))?;
    Ok(raw_script_validator)
}

#[cfg(test)]

mod tests {
    use super::*;
    use naumachia::scripts::context::{pub_key_hash_from_address_if_available, ContextBuilder};
    use naumachia::scripts::ValidatorCode;
    use naumachia::Address;
    use spectrum_crypto::digest::blake2b256_hash;
    use spectrum_ledger::merkle_tree::SparseMerkleProofBuilder;

    #[test]
    fn plutus() {
        let script = get_script().unwrap();

        let owner = Address::from_bech32("addr_test1qpmtp5t0t5y6cqkaz7rfsyrx7mld77kpvksgkwm0p7en7qum7a589n30e80tclzrrnj8qr4qvzj6al0vpgtnmrkkksnqd8upj0").unwrap();

        let owner_pkh = pub_key_hash_from_address_if_available(&owner).unwrap();
        let ctx = ContextBuilder::new(owner_pkh).build_spend(&vec![0, 1, 2], 0);

        let num_leaves: usize = 128;
        let verify_up_to = 127;
        let mut leaves = vec![];
        for i in 0..num_leaves {
            let leaf_data = Vec::from(blake2b256_hash(format!("a{}", i).as_bytes()));
            leaves.push(leaf_data);
        }

        let tree = SparseMerkleProofBuilder::new(leaves).unwrap();

        let proof = tree.build_packed_proof(verify_up_to).unwrap();

        let needed_internal_nodes: Vec<_> = proof
            .needed_internal_nodes
            .into_iter()
            .map(|(level, ix)| InternalNode {
                level: level as i64,
                hash: tree.hashes[ix].clone(),
            })
            .collect();
        let right_peer_hash = proof.right_peer_hash.map(|ix| tree.hashes[ix].clone());
        let packed_proof = PackedSparseMerkleProof {
            leaf_nodes_to_verify: proof.leaf_nodes_to_verify,
            needed_internal_nodes,
            right_peer_hash,
            root_hash: proof.root_hash,
        };

        let res = script.execute(Some(5), packed_proof, ctx).unwrap();
        println!("{:?}", res);
    }
}
