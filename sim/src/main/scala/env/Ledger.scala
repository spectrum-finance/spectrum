package env

sealed trait LotteryMessage
object LotteryMessage:
  case class Register(account: Account)         extends LotteryMessage
  case class CommitMembership(account: Account) extends LotteryMessage
  case class CommitBlock(account: Account)      extends LotteryMessage

  case class TransactionData(id: Long, account: Account, action: Any)
  case class Transaction(data: TransactionData, sig: DsigSignature)

  case class Mempool(pool: Vector[Transaction])

  case class LedgerState(
                          accountPool: Vector[Account],
                          consensusGroupAddress: Vector[Address],
                          participantsVrfKeys: Vector[VrfPublicKey],
                          lastUpdateAt: Long,
                          lastBlockSeqNum: Int
                        )

  case class BlockData(
                        state: LedgerState,
                        txs: Vector[Transaction],
                        slot: Long,
                        leader: Account,
                        randomGeneratedY: String,
                        proofOfLeadership: VrfProof,
                        randomness: String,
                        randomnessProof: VrfProof
                      )
  case class Block(
                    data: BlockData,
                    leaderSignature: KesSignature
                  )

  case class LedgerConfig(
                           maxBlockCapacity: Int,
                           meanBlockTimeMillis: Long,
                           initialRnd: String
                         )

  final case class Ledger(config: LedgerConfig, blocks: Vector[Block], mempool: Mempool):

  def submitTxToMempool(tx: Transaction): Ledger =
  copy(mempool = Mempool(mempool.pool ++ Seq(tx)))

  def formBlockFromMempool(): Block =
  val proposedBlock = blocks.last
  proposedBlock.copy(
  data = proposedBlock.data.copy(
  txs = Vector.empty,
  leader = Account(
  address = Address(""),
  stake = 0L,
  vrfPk = VrfPublicKey(""),
  kesPk = KesPublicKey(""),
  dsigPk = DsigPublicKey("")
  ),
  randomGeneratedY = "",
  proofOfLeadership = VrfProof(""),
  randomness = "",
  randomnessProof = VrfProof("")
  ),
  leaderSignature = KesSignature("")
  )
  val proposedState = proposedBlock.data.state

  (for tx <- mempool.pool
  yield tx.data.action match
  case LotteryMessage.Register(account) =>
  proposedBlock.copy(data =
  proposedBlock.data.copy(
  txs = proposedBlock.data.txs ++ Seq(tx),
  state = proposedState.copy(
  accountPool = proposedState.accountPool ++ Seq(account),
  participantsVrfKeys = proposedState.participantsVrfKeys ++ Seq(account.vrfPk),
  lastBlockSeqNum = proposedState.lastBlockSeqNum + 1
  )
  )
  )
  ).last

  def addBlock(
  b: Block,
  leader: Account,
  y: String,
  proof: VrfProof,
  randomness: String,
  randomnessProof: VrfProof,
  sign: KesSignature
  ): Ledger =
  copy(
  blocks = blocks ++ Seq(
  b.copy(
  data = b.data.copy(
  leader = leader,
  randomGeneratedY = y,
  proofOfLeadership = proof,
  randomness = randomness,
  randomnessProof = randomnessProof
  ),
  leaderSignature = sign
  )
  ),
  mempool = Mempool(mempool.pool.filterNot(b.data.txs.toSet.contains(_)))
  )

  def getLastBlocks(n: Int): Vector[Block] =
  blocks.takeRight(n)

  def getBlock(id: Int): Vector[Block] =
  blocks.filter(_.data.state.lastBlockSeqNum == id)