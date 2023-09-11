{
  val message              = INPUTS(0).R4[Coll[Byte]].get
  val groupGenerator       = INPUTS(0).R5[GroupElement].get
  val groupElementIdentity = INPUTS(0).R6[GroupElement].get
  val committee            = INPUTS(0).R7[Coll[GroupElement]].get
  val threshold            = INPUTS(0).R8[Int].get

  val verificationData = getVar[Coll[((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])) )]](0).get
  val aggregateResponseRaw = getVar[(Coll[Byte], Int)](1).get // z
  val aggregateCommitment = getVar[GroupElement](2).get // Y
 
  // Performs exponentiation of a GroupElement by an unsigned 256bit
  // integer I using the following decomposition of I:
  // Let e = (g, (b, n)). Then this function computes:
  //
  //   g^I == (g^b(0,n))^p * g^(b(n..))
  // where
  //  - b(0,n) is the first n bytes of a positive BigInt `U`
  //  - b(n..) are the remaining bytes starting from index n. These bytes
  //    also represent a positive BigInt `L`.
  //  - p is 340282366920938463463374607431768211456 base 10.
  //  - I == U * p + L
  def myExp(e: (GroupElement, (Coll[Byte], Int))) : GroupElement = {
    val x = e._1
    val y = e._2._1
    val len = e._2._2
    val upper = byteArrayToBigInt(y.slice(0, len))
    val lower = byteArrayToBigInt(y.slice(len, y.size))

    // The following value is 340282366920938463463374607431768211456 base-10.
    val p = byteArrayToBigInt(fromBase64("AQAAAAAAAAAAAAAAAAAAAAA"))
   
    x.exp(upper).exp(p).multiply(x.exp(lower))
  }

  // Converts a big-endian byte representation of an unsigned integer into its
  // equivalent signed representation
  def toSignedBytes(b: Coll[Byte]) : Coll[Byte] = {
    // Note that all integers (including Byte) in Ergoscript are signed. In such
    // a representation, the most-significant bit (MSB) is used to represent the
    // sign; 0 for a positive integer and 1 for negative. Now since `b` is big-
    // endian, the MSB resides in the first byte and MSB == 1 indicates that every
    // bit is used to specify the magnitude of the integer. This means that an
    // extra 0-bit must be prepended to `b` to render it a valid positive signed
    // integer.
    //
    // Now signed integers are negative iff MSB == 1, hence the condition below.
    if (b(0) < 0 ) {
        Coll(0.toByte).append(b)
    } else {
        b
    }
  }

  // Computes a_i = H(X_1, X_2,.., X_n; X_i)
  def calcA(e: (Coll[GroupElement], Int)) : (Coll[Byte], Int) = {
    val committeeMembers = e._1
    val i = e._2
    val bytes = committeeMembers.slice(1, committeeMembers.size).fold(committeeMembers(0).getEncoded, {(b: Coll[Byte], elem: GroupElement) => b.append(elem.getEncoded) })
    val raw = blake2b256(bytes.append(committeeMembers(i).getEncoded))
    val split = raw.size - 16
    val firstInt = toSignedBytes(raw.slice(0, split))
    val concatBytes = firstInt.append(toSignedBytes(raw.slice(split, raw.size)))
    val firstIntNumBytes = firstInt.size
    (concatBytes, firstIntNumBytes)
  }
  
  // Computes X~ = X_0^{a_0} * X_1^{a_1} * ... * X_{n-1}^{a_{n-1}}
  def calcFullAggregateKey(committeeMembers: Coll[GroupElement]) : GroupElement = {
    committeeMembers.fold(
      (groupElementIdentity, 0),
      { (acc: (GroupElement, Int ), x: GroupElement) =>
          val x_acc = acc._1
          val i = acc._2
          (x_acc.multiply(myExp((x, calcA((committeeMembers, i))))), i + 1)
      }
    )._1
  }

  // Computes X'
  def calcPartialAggregateKey(e: (Coll[GroupElement], Coll[Int])) : GroupElement = {
    val committeeMembers = e._1
    val excludedIndices = e._2
    committeeMembers.fold(
      (groupElementIdentity, 0),
      { (acc: (GroupElement, Int), x: GroupElement) =>
          val xAcc = acc._1
          val i = acc._2
          if (excludedIndices.exists { (ix: Int) => ix == i }) {
             (xAcc, i + 1)
          } else {
            (xAcc.multiply(myExp((x, calcA((committeeMembers, i))))), i + 1)
          }
          
      }
    )._1
  }

  // Calculates aggregate commitment Y'
  def calcAggregateCommitment(commitments: Coll[GroupElement]) : GroupElement = {
    commitments.fold(
      groupElementIdentity,
      { (acc: GroupElement, y: GroupElement) =>
          acc.multiply(y)
      }
    )  
  }

  def encodeUnsigned256BitInt(bytes: Coll[Byte]) : (Coll[Byte], Int) = {
    val split = bytes.size - 16
    val firstInt = toSignedBytes(bytes.slice(0, split))
    val concatBytes = firstInt.append(toSignedBytes(bytes.slice(split, bytes.size)))
    val firstIntNumBytes = firstInt.size
    (concatBytes, firstIntNumBytes)
  }
    
  // BIP-0340 uses so-called tagged hashes
  val challengeTag = sha256(Coll(66, 73, 80, 48, 51, 52, 48, 47, 99, 104, 97, 108, 108, 101, 110, 103, 101).map { (x:Int) => x.toByte })
  

  // c
  val challengeRaw = blake2b256(calcFullAggregateKey(committee).getEncoded ++ aggregateCommitment.getEncoded ++ message )
  val challenge    = encodeUnsigned256BitInt(challengeRaw)

  val excludedIndices = verificationData.map { (e: ((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])))) =>
    e._1._1 
  }

  val excludedCommitments = verificationData.map { (e: ((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])))) =>
    e._1._2._1 
  }

  val YDash = calcAggregateCommitment(excludedCommitments)

  val partialAggregateKey = calcPartialAggregateKey((committee, excludedIndices))

  // Verifies that Y'*g^z == (X')^c * Y
  val verifyAggregateResponse = ( myExp((groupGenerator, aggregateResponseRaw)).multiply(YDash) 
      == myExp((partialAggregateKey, challenge)).multiply(aggregateCommitment) )

  val verifySignaturesInExclusionSet =
    verificationData.forall { (e: ((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])))) =>
      val pubKeyTuple = e._1._2
      val s  = e._2._1
      val responseTuple = e._2._2

      val pubKey         = pubKeyTuple._1 // Y_i
      val pkBytes        = pubKeyTuple._2 // encoded x-coordinate of Y_i
      val response       = responseTuple._1 // R in BIP-0340
      val rBytes         = responseTuple._2 // Byte representation of 'r'


      val raw = sha256(challengeTag ++ challengeTag ++ rBytes ++ pkBytes ++ message)
 
      // Note that the output of SHA256 is a collection of bytes that represents an unsigned 256bit integer.
      val split = raw.size - 16
      val first = toSignedBytes(raw.slice(0, split))
      val concatBytes = first.append(toSignedBytes(raw.slice(split, raw.size)))
      val firstIntNumBytes = first.size
      myExp((groupGenerator, s)) ==  myExp((pubKey, (concatBytes, firstIntNumBytes))).multiply(response)
    }

  val verifyThreshold = (committee.size - verificationData.size) >= threshold

  sigmaProp (
    verifyAggregateResponse &&
    verifySignaturesInExclusionSet &&
    verifyThreshold
  )
}