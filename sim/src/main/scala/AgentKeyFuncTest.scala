import scala.math.BigInt
import scala.math
import scala.collection.mutable.ListBuffer
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks
import org.scalatest.matchers.should
import org.scalatest.flatspec.AnyFlatSpec
import org.scalacheck.Gen
import Numeric.Implicits._

import env.*

def iGen: Gen[Int] =
  for i <- Gen.chooseNum(1, 1000)
  yield i

class AgentKeyFuncTest extends AnyFlatSpec with ScalaCheckPropertyChecks with should.Matchers {

  it should s"validate VRF evaluation properties" in
    forAll(iGen) { _ =>
      val epochSeed = "SEED"
      val addString = "TEST"

      val addr = Address(Utility.generateRandomKey())
      val vrf =
        VRF(
          address = addr,
          table = Map(Address("") -> Map(VrfPublicKey("") -> Map("" -> "")))
        )

      val vrfGenReq = VrfGenRequest(sessionId = 0)

      val vrfGen0Resp = vrf.gen(vrfGenReq)
      val vrfGen1Resp = vrf.gen(vrfGenReq)

      val vrfEval0Req = VrfEvalRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        vrfPk = vrfGen0Resp.pk
      )
      val vrfEval1Req = VrfEvalRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        vrfPk = vrfGen1Resp.pk
      )

      val vrfEval0Resp = vrf.eval(vrfEval0Req)
      val vrfEval1Resp = vrf.eval(vrfEval1Req)

      (vrfEval0Resp.y == vrfEval1Resp.y) shouldBe false
    }

  it should s"validate VRF malicious verification properties" in
    forAll(iGen) { _ =>
      val epochSeed = "SEED"
      val addString = "TEST"

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

      val vrfVerifyFairReq = VrfVerifyRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        y = vrfEvalResp.y,
        proof = vrfEvalResp.proof,
        vrfPk = vrfEvalResp.vrf.pk
      )
      val vrfVerifyMalReq = VrfVerifyRequest(
        sessionId = 0,
        epochSeed = epochSeed,
        slot = 42,
        additionalString = addString,
        y = vrfEvalResp.y,
        proof = vrfEvalResp.proof,
        vrfPk = VrfPublicKey(Utility.generateRandomKey())
      )

      val vrfVerifyFairResp = vrfEvalResp.vrf.verify(vrfVerifyFairReq).isValid
      val vrfVerifyMalResp  = vrfEvalResp.vrf.verify(vrfVerifyMalReq).isValid

      vrfVerifyFairResp shouldBe true
      vrfVerifyMalResp shouldBe false
    }
  it should s"validate KES fair and malicious verification properties" in
    forAll(iGen) { _ =>

      val ledger = initLedger(nParticipants = 10)
      val addr   = Address(Utility.generateRandomKey())

      val kes =
        KES(
          address = addr,
          table = Map(Address("") -> Map(1L -> KesPublicKey("")))
        )

      val kesGenReq  = KesGenRequest(sessionId = 0, address = addr)
      val kesGenResp = kes.gen(kesGenReq)

      val kesSignReq = KesSignRequest(
        sessionId = 0,
        address = addr,
        block = ledger.getLastBlocks(1)(0),
        slot = 42
      )
      val kesSignResp = kesGenResp.kes.sign(kesSignReq)

      val kesVerReq = KesVerifyRequest(
        sessionId = 0,
        signedBlock = kesSignResp.signedBlock,
        slot = 42,
        pk = kesGenResp.kes.pk
      )
      val kesVerMalReq = KesVerifyRequest(
        sessionId = 0,
        signedBlock = kesSignResp.signedBlock,
        slot = 42,
        pk = KesPublicKey(Utility.generateRandomKey())
      )

      val kesVerResp    = kesSignResp.kes.verify(kesVerReq)
      val kesVerMalResp = kesSignResp.kes.verify(kesVerMalReq)

      kesVerResp.isValid shouldBe true
      kesVerMalResp.isValid shouldBe false
    }

  it should s"validate DSIG fair and malicious verification properties" in
    forAll(iGen) { _ =>
      val ledger = initLedger(nParticipants = 1)
      val tx = Transaction(
        data = TransactionData(
          id = 1,
          account = ledger.blocks(0).data.state.accountPool(0),
          action = "Hi"
        ),
        sig = DsigSignature("")
      )
      val addr = Address(Utility.generateRandomKey())

      val dsig =
        DSIG(
          address = addr,
          table = Map(Address("") -> DsigPublicKey(""))
        )

      val dsigGenReq  = DsigGenRequest(sessionId = 0, address = addr)
      val dsigGenResp = dsig.gen(dsigGenReq)

      val dsigSignReq = DsigSignRequest(
        sessionId = 0,
        address = addr,
        tx = tx
      )
      val dsigSignResp = dsigGenResp.dsig.sign(dsigSignReq)

      val dsigVerReq =
        DsigVerifyRequest(sessionId = 0, signedTx = dsigSignResp.signedTx, pk = dsigGenResp.dsig.pk)

      val dsigVerMalReq = DsigVerifyRequest(
        sessionId = 0,
        signedTx = dsigSignResp.signedTx,
        pk = DsigPublicKey(Utility.generateRandomKey())
      )

      val dsigVerResp    = dsigGenResp.dsig.verify(dsigVerReq)
      val dsigVerMalResp = dsigGenResp.dsig.verify(dsigVerMalReq)

      dsigVerResp.isValid shouldBe true
      dsigVerMalResp.isValid shouldBe false
    }
}
