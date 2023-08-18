use aiken/builtin.{blake2b_256}
use aiken/bytearray
use aiken/list
use aiken/transaction/credential.{VerificationKey}

/// Custom type
pub type Datum {
  /// Aggregated public key of the current committee.
  aggregated_pk: VerificationKey,
  message: ByteArray,
}

pub type InternalNode {
  level: Int,
  hash: ByteArray,
}

/// The aggregated public key of the current committee
pub type Redeemer {
  leaves: List<ByteArray>,
  internal_nodes: List<InternalNode>,
  peer_leaf_hash: Option<ByteArray>,
  merkle_root_hash: ByteArray,
}

// merkle_root_signature: ByteArray,

type IndexedRow =
  List<(Int, ByteArray)>

pub fn sparse_merkle_proof(
  leaves: List<ByteArray>,
  internal_nodes: List<InternalNode>,
  peer_leaf_hash: Option<ByteArray>,
  root_hash: ByteArray,
) -> Bool {
  let f =
    fn(i, h) { (i, bytearray.push(blake2b_256(h), 0)) }
  let indexed_leaves = list.indexed_map(leaves, f)
  let prefixed_hashed_leaves =
    when peer_leaf_hash is {
      Some(hash) ->
        list.concat(indexed_leaves, [(list.length(indexed_leaves), hash)])
      None -> indexed_leaves
    }
  when rec(prefixed_hashed_leaves, internal_nodes, 0) is {
    Some(bytes) -> root_hash == bytes
    None -> False
  }
}

/// 
/// Parameters:
///  - `internal_nodes` is a list of (level, prefixed_hash) elements, where
///    `prefixed_hash` is a 1-prefixed Merkle-tree hash at the given `level`. 
fn process_next_level(
  nodes: IndexedRow,
  next_level: Int,
  internal_nodes: List<InternalNode>,
) -> Option<IndexedRow> {
  when list.tail(nodes) is {
    Some(rest) -> {
      let computed_nodes =
        list.filter_map(
          list.zip(nodes, rest),
          fn(x) {
            if x.1st.1st % 2 == 0 {
              let left = x.1st.2nd
              let right = x.2nd.2nd
              Some(
                bytearray.push(bytearray.concat(left, right) |> blake2b_256, 1),
              )
            } else {
              None
            }
          },
        )
      let internal_nodes_at_level =
        list.filter_map(
          internal_nodes,
          fn(x) {
            if x.level == next_level {
              Some(x.hash)
            } else {
              None
            }
          },
        )
      list.indexed_map(
        list.concat(computed_nodes, internal_nodes_at_level),
        fn(i, e) { (i, e) },
      )
        |> Some
    }
    _ -> None
  }
}

fn rec(
  prefixed_nodes: List<(Int, ByteArray)>,
  internal_nodes: List<InternalNode>,
  level: Int,
) -> Option<ByteArray> {
  when process_next_level(prefixed_nodes, level + 1, internal_nodes) is {
    Some([(_, bytes)]) -> Some(bytes)
    Some(next_level) -> rec(next_level, internal_nodes, level + 1)
    None -> None
  }
}
