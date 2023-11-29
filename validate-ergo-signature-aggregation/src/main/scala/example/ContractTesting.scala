package example

import cats.effect._, org.http4s._, org.http4s.dsl.io._
import com.comcast.ip4s._
import org.ergoplatform.ErgoAddressEncoder
import scala.concurrent.duration._
import org.ergoplatform.appkit.config.{ErgoNodeConfig, ErgoToolConfig}
import org.ergoplatform.appkit.impl.ErgoTreeContract
import io.circe._, io.circe.generic.auto._, io.circe.parser._, io.circe.syntax._
import scala.collection.JavaConverters._
import org.ergoplatform.sdk.ErgoToken
import org.ergoplatform.appkit.{
  ErgoClient,
  RestApiErgoClient,
  NetworkType,
  ConstantsBuilder,
  BlockchainContext,
  ErgoContract
}
import org.ergoplatform.appkit.Address
import org.ergoplatform.appkit.SignedTransaction
import org.ergoplatform.appkit.ReducedTransaction
import special.collection.Coll
import special.sigma.GroupElement
import sigmastate.serialization.ValueSerializer
import scorex.util.encode.Base64
import sigmastate.serialization.ErgoTreeSerializer
import io.circe.Json
import sigmastate.serialization.DataJsonEncoder
import org.ergoplatform.appkit.UnsignedTransaction
import org.ergoplatform.wallet.boxes.ErgoBoxSerializer
import org.ergoplatform.UnsignedInput
import org.ergoplatform.ErgoLikeTransaction
import org.ergoplatform.sdk.AppkitProvingInterpreter
import org.ergoplatform.ErgoBox
import org.ergoplatform.appkit.ErgoValue
import scorex.util.encode.Base58
import scala.util.Success
import scala.util.Failure
import scorex.util.encode.Base16
import sigmastate.Values._
import sigmastate.serialization.ConstantSerializer
import sigmastate.lang.DeserializationSigmaBuilder
import sigmastate.serialization.SigmaSerializer
import sigmastate.SType
import sigmastate.SCollection
import sigmastate.SInt
import sigmastate.SAvlTree
import sigmastate.SGroupElement
import sigmastate._
import org.ergoplatform.appkit.ContextVar
import org.ergoplatform.appkit.scalaapi.ErgoValueBuilder
import org.ergoplatform.appkit.AppkitIso
import org.ergoplatform.sdk.Iso
import org.ergoplatform.appkit.ErgoType
import org.ergoplatform.appkit.commands.ErgoIdPType
import scala.io.Source
import org.http4s.ember.server.EmberServerBuilder
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.implicits._
import io.circe.syntax._
import org.http4s.circe._
import io.circe.literal._
import org.http4s.circe.CirceEntityDecoder._
import org.ergoplatform.sdk.wallet.secrets.SecretKey
import sigmastate.serialization.DataSerializer
import org.ergoplatform.sdk.ErgoId
import scorex.crypto.authds.ADDigest

object ContractTesting extends IOApp {
  case class SignatureValidationInput(
      contract: String,
      exclusionSet: String,
      aggregateResponse: String,
      aggregateCommitment: String,
      generator: String,
      identity: String,
      committee: String,
      md: String,
      threshold: String,
      hashBytes: String
  )

  case class VaultValidationInput(
      signatureInput: SignatureValidationInput,
      terminalCells: String,
      startingAvlTree: String,
      avlProof: String,
      epochLength: Int,
      currentEpoch: Int
  )

  case class ValidateResponse(
      result: Boolean,
      txCost: Int,
      txSizeInKb: Double,
      validationTimeMillis: Int
  )

  case class ErrorResponse(error: String)

  implicit val ValidateEncoder: Encoder[ValidateResponse] =
    Encoder.instance { (v: ValidateResponse) =>
      json"""{"result": ${v.result}, "txCost": ${v.txCost}, "validationTimeMillis": ${v.validationTimeMillis},"txSizeInKb": ${v.txSizeInKb} }"""
    }

  implicit val ErrorResponseEncoder: Encoder[ErrorResponse] =
    Encoder.instance { (e: ErrorResponse) =>
      json"""{"error": ${e.error}}"""
    }

  val ergoClient: ErgoClient = RestApiErgoClient.create(
    "http://213.239.193.208:9053/",
    NetworkType.MAINNET,
    "",
    "https://api.ergoplatform.com/api/v1/"
  )

  val service = HttpRoutes.of[IO] { case req @ PUT -> Root / "validateVault" =>
    req.as[VaultValidationInput].flatMap { input =>
      try {
        val response = ergoClient.execute(ctx => {
          validateVault(ctx, input)
        })
        println(response.asJson)
        Ok(response.asJson)
      } catch {
        case e: Throwable => {
          println(e.getMessage())
          Ok("")
        }
      }
    }
  }

  override def run(args: List[String]): IO[ExitCode] =
    EmberServerBuilder
      .default[IO]
      // .withHost(ipv4"127.0.0.1")
      .withHost(ipv4"0.0.0.0")
      .withPort(port"8080")
      .withHttpApp(service.orNotFound)
      .build
      .use(_ => IO.never)
      .as(ExitCode.Success)

  def validateVault(
      ctx: BlockchainContext,
      input: VaultValidationInput
  ): Either[ErrorResponse, ValidateResponse] = {

    val combined = for {
      address <- ErgoAddressEncoder.Mainnet.fromString(
        input.signatureInput.contract
      )
      exclusionSetBytes <- Base16.decode(input.signatureInput.exclusionSet)
      aggregateResponseBytes <- Base16.decode(
        input.signatureInput.aggregateResponse
      )
      aggregateCommitmentBytes <- Base16.decode(
        input.signatureInput.aggregateCommitment
      )
      generatorBytes <- Base16.decode(input.signatureInput.generator)
      identityBytes <- Base16.decode(input.signatureInput.identity)
      mdBytes <- Base16.decode(input.signatureInput.md)
      committeeBytes <- Base16.decode(input.signatureInput.committee)
      thresholdBytes <- Base16.decode(input.signatureInput.threshold)
      hashBytes <- Base16.decode(input.signatureInput.hashBytes)
      terminalCellsBytes <- Base16.decode(input.terminalCells)
      startingAvlTreeBytes <- Base16.decode(input.startingAvlTree)
      avlProofBytes <- Base16.decode(input.avlProof)

    } yield {
      (
        address,
        exclusionSetBytes,
        aggregateResponseBytes,
        aggregateCommitmentBytes,
        generatorBytes,
        identityBytes,
        mdBytes,
        committeeBytes,
        thresholdBytes,
        hashBytes,
        terminalCellsBytes,
        startingAvlTreeBytes,
        avlProofBytes
      )
    }

    combined match {
      case Success(
            (
              address,
              exclusionSetBytes,
              aggregateResponseBytes,
              aggregateCommitmentBytes,
              generatorBytes,
              identityBytes,
              mdBytes,
              committeeBytes,
              thresholdBytes,
              hashBytes,
              terminalCellsBytes,
              startingAvlTreeBytes,
              avlProofBytes
            )
          ) => {
        val validationContract = ctx.newContract(address.script)

        val prover = ctx
          .newProverBuilder()
          .withDLogSecret(BigInt.apply(0).bigInteger)
          .build()

        val exclusionSetConstant =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(exclusionSetBytes))
            .asInstanceOf[Values.Constant[
              SCollection[STuple]
            ]]

        val terminalCellsConstant =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(terminalCellsBytes))
            .asInstanceOf[Values.Constant[
              SCollection[STuple]
            ]]

        val aggregateResponse = ConstantSerializer(
          DeserializationSigmaBuilder
        )
          .deserialize(SigmaSerializer.startReader(aggregateResponseBytes))
          .asInstanceOf[Values.Constant[STuple]]

        val aggregateCommitment =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(
              SigmaSerializer.startReader(aggregateCommitmentBytes)
            )
            .asInstanceOf[Values.Constant[SGroupElement.type]]

        val generator =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(generatorBytes))
            .asInstanceOf[Values.Constant[SGroupElement.type]]

        val identity =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(identityBytes))
            .asInstanceOf[Values.Constant[SGroupElement.type]]

        val md =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(mdBytes))
            .asInstanceOf[Values.Constant[SCollection[SByte.type]]]

        val committee =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(committeeBytes))
            .asInstanceOf[Values.Constant[SCollection[SGroupElement.type]]]

        val threshold =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(thresholdBytes))
            .asInstanceOf[Values.Constant[SInt.type]]

        val hash =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(hashBytes))
            .asInstanceOf[Values.Constant[SCollection[SByte.type]]]

        val tb = ctx.newTxBuilder()

        val currentHeight = tb.getCtx().getHeight()

        val aggrResponse =
          aggregateResponse.value.asInstanceOf[Tuple2[Coll[Byte], Int]]
        println(aggrResponse)

        val exclusionSet = exclusionSetConstant.value
          .asInstanceOf[Coll[Tuple2[
            Tuple2[Int, Tuple2[GroupElement, Coll[Byte]]],
            Tuple2[Tuple2[Coll[Byte], Int], Tuple2[GroupElement, Coll[
              Byte
            ]]]
          ]]]
          .toArray

        val terminalCells = terminalCellsConstant.value
          .asInstanceOf[Coll[Tuple2[
            Long,
            Tuple2[Coll[Byte], Coll[Tuple2[Coll[Byte], Long]]]
          ]]]
          .toArray

        type TerminalCellType =
          (
              java.lang.Long,
              (
                  Coll[java.lang.Byte],
                  Coll[(Coll[java.lang.Byte], java.lang.Long)]
              )
          )

        val terminalCellsMapped: Array[TerminalCellType] =
          terminalCells.map(e => {
            val nanoErgs = ErgoValue.of(e._1)
            val propBytes = ErgoValue.of(e._2._1.toArray)
            val tokensMapped =
              ErgoValue.of(
                e._2._2.toArray.map(f => {
                  val tokenId = ErgoValue.of(f._1.toArray)
                  val amount = ErgoValue.of(f._2)
                  ErgoValue.pairOf(tokenId, amount).getValue()
                }),
                ErgoType.pairType(
                  ErgoType.collType(ErgoType.byteType()),
                  ErgoType.longType()
                )
              )
            ErgoValue
              .pairOf(
                nanoErgs,
                ErgoValue.pairOf(propBytes, tokensMapped)
              )
              .getValue()
          })

        type ExclusionSetType = (
            (Integer, (GroupElement, Coll[java.lang.Byte])),
            (
                (Coll[java.lang.Byte], Integer),
                (GroupElement, Coll[java.lang.Byte])
            )
        )

        val eSetMapped: Array[
          ExclusionSetType
        ] = exclusionSet.map(e => {
          val excludedIx = ErgoValue.of(e._1._1)
          val yi = ErgoValue.of(e._1._2._1)
          val yiBytes = ErgoValue.of(e._1._2._2.toArray)
          val yiTuple = ErgoValue.pairOf(yi, yiBytes)
          val leftTuple = ErgoValue.pairOf(excludedIx, yiTuple)

          val z = ErgoValue.of(e._2._1._1.toArray)
          val zIx = ErgoValue.of(e._2._1._2)
          val response = ErgoValue.of(e._2._2._1)
          val rBytes = ErgoValue.of(e._2._2._2.toArray)
          val rightTuple = ErgoValue.pairOf(
            ErgoValue.pairOf(z, zIx),
            ErgoValue.pairOf(response, rBytes)
          )
          ErgoValue.pairOf(leftTuple, rightTuple).getValue()
        })

        val geAndCollBytes = ErgoType.pairType(
          ErgoType.groupElementType(),
          ErgoType.collType(ErgoType.byteType())
        )

        val exclusionSetType: ErgoType[ExclusionSetType] =
          ErgoType
            .pairType(
              ErgoType.pairType(ErgoType.integerType(), geAndCollBytes),
              ErgoType.pairType(
                ErgoType.pairType(
                  ErgoType.collType(ErgoType.byteType()),
                  ErgoType.integerType()
                ),
                geAndCollBytes
              )
            )

        val eSet: ErgoValue[Coll[ExclusionSetType]] =
          ErgoValue.of(eSetMapped, exclusionSetType)

        val terminalCellType: ErgoType[TerminalCellType] =
          ErgoType.pairType(
            ErgoType.longType(),
            ErgoType.pairType(
              ErgoType.collType(ErgoType.byteType()),
              ErgoType.collType(
                ErgoType.pairType(
                  ErgoType.collType(ErgoType.byteType()),
                  ErgoType.longType()
                )
              )
            )
          )

        val termCells: ErgoValue[Coll[TerminalCellType]] =
          ErgoValue.of(terminalCellsMapped, terminalCellType)

        val startingAvlTree =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(startingAvlTreeBytes))
            .asInstanceOf[Values.Constant[SAvlTree.type]]

        val avlTree = startingAvlTree.value

        val avlTreeData = AvlTreeData(
          ADDigest(avlTree.digest.toArray),
          AvlTreeFlags(
            avlTree.isInsertAllowed,
            avlTree.isUpdateAllowed,
            avlTree.isRemoveAllowed
          ),
          avlTree.keyLength,
          avlTree.valueLengthOpt
        )

        val avlProof =
          ConstantSerializer(DeserializationSigmaBuilder)
            .deserialize(SigmaSerializer.startReader(avlProofBytes))
            .asInstanceOf[Values.Constant[SCollection[SByte.type]]]

        val dummyErgoContract = new ErgoTreeContract(
          Address.create("4MQyML64GnzMxZgm").getErgoAddress.script,
          NetworkType.MAINNET
        )

        val minersFeeAddress =
          Address
            .create(
              "2iHkR7CWvD1R4j1yZg5bkeDRQavjAaVPeTDFGGLZduHyfWMuYpmhHocX8GJoaieTx78FntzJbCBVL6rf96ocJoZdmWBL2fci7NqWgAirppPQmZ7fN9V6z13Ay6brPriBKYqLp1bT2Fk4FkFLCfdPpe"
            )
            .getErgoAddress()

        val INITIAL_VAULT_NANOERG_BALANCE = 2e9.toLong
        val nanoergs_to_distribute = terminalCells.map(e => e._1).sum

        val inputBoxBuilder = tb
          .outBoxBuilder()
          .creationHeight(currentHeight - 10)
          .contract(validationContract)
          .value(INITIAL_VAULT_NANOERG_BALANCE + nanoergs_to_distribute)

        val outBoxes = terminalCells.map(e => {

          val ergoTree =
            ErgoTreeSerializer.DefaultSerializer.deserializeErgoTree(
              e._2._1.toArray
            )
          val builder = tb
            .outBoxBuilder()
            .value(e._1)
            .contract(new ErgoTreeContract(ergoTree, NetworkType.MAINNET))

          val outbox =
            if (e._2._2.isEmpty) {
              builder.build()
            } else {

              // Add token to the input box.
              inputBoxBuilder
                .tokens(
                  e._2._2.toArray.map(e =>
                    ErgoToken(
                      new ErgoId(e._1.toArray.map(b => b.byteValue())),
                      e._2
                    )
                  ): _*
                )
              builder
                .tokens(
                  e._2._2.toArray.map(e =>
                    ErgoToken(
                      new ErgoId(e._1.toArray.map(b => b.byteValue())),
                      e._2
                    )
                  ): _*
                )
                .build()
            }
          outbox
        })

        val withdrawalUTXOsNumKb =
          outBoxes.map(o => o.getBytesWithNoRef().length).sum.toDouble / 1024.0
        println(s"# bytes in withdrawals: $withdrawalUTXOsNumKb")

        val changeForMiner = 1000000.toLong

        val userOutBox = tb
          .outBoxBuilder()
          .contract(validationContract)
          .value(INITIAL_VAULT_NANOERG_BALANCE - changeForMiner)
          .build()

        val outputs = outBoxes :+ userOutBox

        println(exclusionSet)

        val committeeArray: Array[GroupElement] = committee.value.toArray;

        val inputBox = inputBoxBuilder
          .build()
          .convertToInputWith(
            "ce552663312afc2379a91f803c93e2b10b424f176fbc930055c10def2fd88a5d",
            0
          )
          .withContextVars(
            ContextVar.of(0.toByte, eSet),
            ContextVar
              .of(
                5.toByte,
                ErgoValue.pairOf(
                  ErgoValue.of(aggrResponse._1.toArray),
                  ErgoValue.of(aggrResponse._2)
                )
              ),
            ContextVar.of(1.toByte, ErgoValue.of(aggregateCommitment.value)),
            ContextVar.of(6.toByte, ErgoValue.of(md.value.toArray)),
            ContextVar.of(9.toByte, ErgoValue.of(threshold.value)),
            ContextVar.of(2.toByte, termCells),
            ContextVar.of(7.toByte, ErgoValue.of(avlTreeData)),
            ContextVar.of(3.toByte, ErgoValue.of(avlProof.value.toArray)),
            ContextVar.of(8.toByte, ErgoValue.of(changeForMiner))
          )

        val bytesInContextExtension =
          (exclusionSetBytes.length + aggregateResponseBytes.length
            + aggregateCommitmentBytes.length + mdBytes.length + thresholdBytes.length + terminalCellsBytes.length
            + startingAvlTreeBytes.length + avlProofBytes.length).toDouble / 1024.0

        val MAX_COMMITTEE_IN_BOX = 118
        val NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX = 115
        val num_boxes = committeeArray.length / MAX_COMMITTEE_IN_BOX + 1
        val dataInputs = committeeArray
          .grouped(MAX_COMMITTEE_IN_BOX)
          .zipWithIndex
          .map(tup => {
            val elements = tup._1
            val ix = tup._2
            if (ix == 0) {
              val currentEpoch = input.currentEpoch
              val epochLength = input.epochLength

              // The following starting height for the vault ensures that the
              // current height is within the epoch boundaries.
              val vaultStart = currentHeight - epochLength * currentEpoch + 1
              val vaultParameters =
                Array(num_boxes, currentEpoch, epochLength, vaultStart)
              tb.outBoxBuilder()
                .contract(dummyErgoContract)
                .registers(
                  ErgoValue.of(elements, ErgoType.groupElementType()),
                  ErgoValue.of(ix),
                  ErgoValue.of(vaultParameters),
                  ErgoValue.of(generator.value),
                  ErgoValue.of(identity.value),
                  ErgoValue.of(hash.value.toArray)
                )
                .value(INITIAL_VAULT_NANOERG_BALANCE)
                .build()
                .convertToInputWith(
                  "ce552663312afc2379a91f803c93e2b10b424f176fbc930055c10def2fd88a5d",
                  0
                )
            } else {
              tb.outBoxBuilder()
                .contract(dummyErgoContract)
                .registers(
                  ErgoValue.of(elements, ErgoType.groupElementType()),
                  ErgoValue.of(ix)
                )
                .value(INITIAL_VAULT_NANOERG_BALANCE)
                .build()
                .convertToInputWith(
                  "ce552663312afc2379a91f803c93e2b10b424f176fbc930055c10def2fd88a5d",
                  0
                )

            }
          })

        val tx = tb
          .boxesToSpend(Seq(inputBox).asJava)
          .addDataInputs(dataInputs.toArray: _*)
          .outputs(outputs: _*)
          .sendChangeTo(minersFeeAddress)
          .build()
        try {
          val reduced = prover.reduce(tx, 1000)
          println(s"TX cost: ${reduced.getCost()}")
        } catch {
          case e: Exception => {
            print(e)
          }
        }

        val startTimeInMillis = System.currentTimeMillis()
        val signed = prover.sign(tx)
        val endTimeInMillis = System.currentTimeMillis()
        val executionTimeInMillis = endTimeInMillis - startTimeInMillis
        val txSize = signed.toBytes().length.toFloat / 1024.0

        val validationContractNumBytes =
          validationContract.getErgoTree().bytes.length.toDouble / 1024.0
        println(
          s"The block of code took $executionTimeInMillis milliseconds to execute. Size: $txSize Kb, bytes in context extension: $bytesInContextExtension Kb, # contract_bytes: $validationContractNumBytes"
        )

        // println(s"signed tx: ${signed.toJson(false)}")

        Right(
          ValidateResponse(
            true,
            signed.getCost(),
            txSize,
            executionTimeInMillis.toInt
          )
        )
      }
      case Failure(exception) => {
        println(exception)
        Left(ErrorResponse(exception.toString()))
      }
    }

  }
}
