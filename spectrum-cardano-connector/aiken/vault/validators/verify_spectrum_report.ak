use aiken/transaction.{ScriptContext}
use vault/types

validator {
  fn release_value(
    _datum: Option<Int>,
    redeemer: types.Redeemer,
    _ctx: ScriptContext,
  ) {
    let types.Redeemer {
      merkle_root_hash,
      leaves,
      internal_nodes,
      peer_leaf_hash,
    } = redeemer
    types.sparse_merkle_proof(
      leaves,
      internal_nodes,
      peer_leaf_hash,
      merkle_root_hash,
    )
  }
}
