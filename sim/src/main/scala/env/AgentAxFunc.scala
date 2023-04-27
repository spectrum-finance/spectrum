package env

import pt.kcry.sha.Sha2_256

import scala.language.implicitConversions

// Utility data transformation functions:
object Utility:
  implicit def bytesToHex(o: Array[Byte]): String =
    o.iterator.map(b => String.format("%02x", Byte.box(b))).mkString("")

  def generateRandomKey(size: Int = 32): String =
    val randomBytes = Array.fill[Byte](size)(0)
    scala.util.Random.nextBytes(randomBytes)
    bytesToHex(randomBytes)

  def getHash(v: String): String =
    val hashed = Sha2_256.hash(v.getBytes())
    bytesToHex(hashed)

  def hexToInt(s: String, lVrf: Int): Long =
    var num = s.toList.map("0123456789abcdef".indexOf(_)).reduceLeft(_ * 16 + _)
    if (num < 0) num = -num
    ((num.toDouble * math.pow(2, lVrf)) / Int.MaxValue).toLong

// Functions to evaluate lottery result:
object LotteryEvaluator:
  implicit def getLotteryThreshold(
      lVrf: Int,
      participantStake: Long,
      totalStake: Long,
      selectionFraction: Double
  ): Long =
    val phiValue = 1 - math.pow(1 - selectionFraction, participantStake.toDouble / totalStake)
    (math.pow(2, lVrf) * phiValue).toLong

  def result(
      randomY: String,
      lVrf: Int,
      participantStake: Long,
      totalStake: Long,
      selectionFraction: Double
  ): Boolean =
    val randomNumber = Utility.hexToInt(s = randomY, lVrf = lVrf)
    val t = getLotteryThreshold(
      lVrf = lVrf,
      participantStake = participantStake,
      totalStake = totalStake,
      selectionFraction = selectionFraction
    )
    randomNumber < t
