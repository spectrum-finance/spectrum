package env

case class Rejection()

case class BlockId(value: Long)

/** @type
  *   B - Block
  * @type
  *   S - State
  */
trait Ledger[B, S, F[_]]:
  /** Add a new block to the ledger.
    */
  def add(block: B): F[Either[Rejection, S]]

  /** Get all blocks at the given height.
    */
  def getAll(height: Int): F[List[B]]

  /** Get specific block.
    */
  def get(id: BlockId): F[Option[B]]
