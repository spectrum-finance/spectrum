use aiken/builtin.{verify_ecdsa_secp256k1_signature}
use aiken/transaction.{ScriptContext}
use vault/types.{Datum, Redeemer}

validator {
  fn release_value(datum: Datum, redeemer: Redeemer, _ctx: ScriptContext) {
    let types.Redeemer {
      merkle_root_hash,
      leaves,
      internal_nodes,
      peer_leaf_hash,
      merkle_root_signature,
    } = redeemer
    verify_ecdsa_secp256k1_signature(
      datum.aggregated_pk,
      merkle_root_hash,
      merkle_root_signature,
    ) && types.sparse_merkle_proof(
      leaves,
      internal_nodes,
      peer_leaf_hash,
      merkle_root_hash,
    )
  }
}
