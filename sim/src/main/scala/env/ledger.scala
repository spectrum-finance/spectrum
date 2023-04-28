package sim.env

case class Account(value: String)

case class Transaction(id: Long, account: Account, change: Long)

case class BlockId(value: Long)

case class Block(id: BlockId, txs: Vector[Transaction], seqNum: Int)

trait Ledger[F[_]]:
  /** Add a new block to the ledger.
    */
  def add(block: Block): F[Unit]

  /** Get all blocks at the given height.
    */
  def getAll(height: Int): F[List[Block]]

  /** Get specific block.
    */
  def get(id: BlockId): F[Option[Block]]
