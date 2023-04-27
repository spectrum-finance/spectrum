import scala.math.BigInt
import scala.math
import scala.collection.mutable.ListBuffer
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks
import org.scalatest.matchers.should
import org.scalatest.flatspec.AnyFlatSpec
import org.scalacheck.Gen
import Numeric.Implicits._

import env.*

def runLeaderLottery(
    lData: LedgerState,
    epochSeed: String,
    addString: String,
    slot: Long,
    lVrf: Int,
    selectionFraction: Double
): Int =
  var nLeaders = 0
  for (i <- 1 until lData.participantsVrfKeys.size)
    val pk = lData.participantsVrfKeys(i).value
    val vrfInstance = VRF(
      address = Address(pk),
      pk = VrfPublicKey(pk),
      table = Map(Address(pk) -> Map(VrfPublicKey(pk) -> Map("" -> "")))
    )

    val vrfEvalReq = VrfEvalRequest(
      sessionId = 0,
      epochSeed = epochSeed,
      slot = slot,
      additionalString = addString,
      vrfPk = VrfPublicKey(pk)
    )
    val vrfEvalResp = vrfInstance.eval(vrfEvalReq)

    if LotteryEvaluator.result(
        vrfEvalResp.y,
        lVrf,
        lData.accountPool(i).stake,
        lData.accountPool.map(_.stake).sum,
        selectionFraction
      )
    then nLeaders += 1
  nLeaders

class ElectionLogicTest extends AnyFlatSpec with ScalaCheckPropertyChecks with should.Matchers {

  it should s"validate lottery results distribution" in {
    val epochSeed         = "SEED"
    val addString         = "TEST"
    val n                 = 1000
    val lVrf              = 10
    val stake             = 10
    val totalStake        = 100
    val selectionFraction = 0.2

    var winsList = ListBuffer[Boolean]()

    for (_ <- 1 to n)

      val addr = Address(Utility.generateRandomKey())
      val vrf =
        VRF(
          address = addr,
          table = Map(Address("") -> Map(VrfPublicKey("") -> Map("" -> "")))
        )
      val vrfGenReq  = VrfGenRequest(sessionId = 0)
      val vrfGenResp = vrf.gen(vrfGenReq)

      val vrfEvalReq = VrfEvalRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        vrfPk = vrfGenResp.pk
      )
      val vrfEvalResp = vrfGenResp.vrf.eval(vrfEvalReq)

      val isWinner =
        LotteryEvaluator.result(vrfEvalResp.y, lVrf, stake, totalStake, selectionFraction)

      winsList = winsList :+ isWinner

    (winsList
      .count(_ == true)
      .toDouble / n) - stake / totalStake * selectionFraction <= 0.1 shouldBe true
  }

  it should s"validate election probability is linear" in {
    val epochSeed         = "SEED"
    val addString         = "TEST"
    val n                 = 500
    val lVrf              = 10
    val selectionFraction = 0.2

    val stake0     = 10
    val stake1     = 2 * stake0
    val stake2     = 3 * stake0
    val totalStake = stake0 + stake1 + stake2

    var winsList0 = ListBuffer[Boolean]()
    var winsList1 = ListBuffer[Boolean]()
    var winsList2 = ListBuffer[Boolean]()

    for (_ <- 1 to n)

      val addr = Address(Utility.generateRandomKey())
      val vrf =
        VRF(
          address = addr,
          table = Map(Address("") -> Map(VrfPublicKey("") -> Map("" -> "")))
        )
      val vrfGenReq  = VrfGenRequest(sessionId = 0)
      val vrfGenResp = vrf.gen(vrfGenReq)

      val vrfEvalReq = VrfEvalRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        vrfPk = vrfGenResp.pk
      )
      val vrfEvalResp0 = vrfGenResp.vrf.eval(vrfEvalReq)
      val vrfEvalResp1 =
        vrfGenResp.vrf.eval(vrfEvalReq.copy(vrfPk = VrfPublicKey(Utility.generateRandomKey())))
      val vrfEvalResp2 =
        vrfGenResp.vrf.eval(vrfEvalReq.copy(vrfPk = VrfPublicKey(Utility.generateRandomKey())))

      val isWinner0 =
        LotteryEvaluator.result(vrfEvalResp0.y, lVrf, stake0, totalStake, selectionFraction)
      val isWinner1 =
        LotteryEvaluator.result(vrfEvalResp1.y, lVrf, stake1, totalStake, selectionFraction)
      val isWinner2 =
        LotteryEvaluator.result(vrfEvalResp2.y, lVrf, stake2, totalStake, selectionFraction)

      winsList0 = winsList0 :+ isWinner0
      winsList1 = winsList1 :+ isWinner1
      winsList2 = winsList2 :+ isWinner2

    val fr0 = winsList0.count(_ == true).toDouble / n
    val fr1 = winsList1.count(_ == true).toDouble / n
    val fr2 = winsList2.count(_ == true).toDouble / n

    math.abs(2 - (fr1 / fr0)) <= 0.5 shouldBe true
    math.abs(3 - (fr2 / fr0)) <= 0.5 shouldBe true
    math.abs(1.5 - (fr2 / fr1)) <= 0.5 shouldBe true
  }

  it should s"validate lottery results" in {
    val epochSeed         = "SEED"
    val addString         = "TEST"
    val nConsensusMembers = 100
    val nSlots            = 1000
    val lVrf              = 8 // NB: important to select correctly
    val selectionFraction = 0.2

    val ledgerState = genInitialLedgerState(groupSize = nConsensusMembers)

    var nLeaders = 0
    for (sl <- 1 to nSlots)
      nLeaders += runLeaderLottery(ledgerState, epochSeed, addString, sl, lVrf, selectionFraction)
    math.abs(nLeaders.toDouble / nSlots - selectionFraction) <= 0.2 shouldBe true
  }
}
