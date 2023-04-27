package env

import org.scalacheck.Gen

import scala.collection.mutable.ListBuffer
import scala.language.postfixOps

def genInitialLedgerState(groupSize: Int): LedgerState =
  val rand = new scala.util.Random
  val accPool =
    (for (_ <- 1 to groupSize)
      yield
        val address   = Address(Utility.generateRandomKey())
        val vrfGenReq = VrfGenRequest(sessionId = 0)
        val vrfGenResp = VRF(
          address = address,
          table = Map(Address("") -> Map(VrfPublicKey("") -> Map("" -> "")))
        ).gen(vrfGenReq)

        val kesGenReq = KesGenRequest(sessionId = 0, address = address)
        val kesGenResp =
          KES(address = address, table = Map(Address("") -> Map(1L -> KesPublicKey(""))))
            .gen(kesGenReq)

        val dsigGenReq = DsigGenRequest(sessionId = 0, address = address)
        val dsigGenResp =
          DSIG(address = address, table = Map(Address("") -> DsigPublicKey(""))).gen(dsigGenReq)

        val stake = rand.nextInt(Int.MaxValue)

        Account(
          address = address,
          stake = stake,
          vrfPk = vrfGenResp.pk,
          kesPk = kesGenResp.pk,
          dsigPk = dsigGenResp.pk
        )
    ).toVector

  LedgerState(
    accountPool = accPool,
    consensusGroupAddress = accPool.map(_.address),
    participantsVrfKeys = accPool.map(_.vrfPk),
    lastUpdateAt = 0,
    lastBlockSeqNum = 0
  )

def initLedger(
    nParticipants: Int,
    maxBlockCapacity: Int = 100,
    meanBlockTimeMillis: Long = 1000L,
    initialRnd: String = "SEED"
): Ledger =
  val initState = genInitialLedgerState(nParticipants)
  val conf = LedgerConfig(
    maxBlockCapacity = maxBlockCapacity,
    meanBlockTimeMillis = meanBlockTimeMillis,
    initialRnd = initialRnd
  )

  val blocks = Vector(
    Block(
      data = BlockData(
        txs = Vector.empty,
        slot = 1L,
        state = initState,
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
  )

  Ledger(config = conf, blocks = blocks, mempool = Mempool(Vector.empty))
