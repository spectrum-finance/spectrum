{ // ===== Contract Information ===== //
  // Name: VaultSignatureVerification
  // Description: Contract that validates the aggregated signature of a message digest 'm' and
  // also verifies that all transactions in a given report were notarized by the current committee
  // (validator set).
  //
  // This is how the overall process works:
  //  1. The 'report' consists of a collection of 'terminal cells', which describes the value
  //     (ERGs and tokens) that will be transferred to a particular address.
  //  2. Each terminal cell is encoded as bytes which are used in an insertion operation of an AVL
  //     tree.
  //  3. The insertions are performed off-chain and the resulting AVL tree digest is hashed by
  //     blake2b256; this value is the message digest 'm'.
  //  4. The committee performs the signature aggregation process to sign 'm'.
  //  5. This contract verifies that the committee signed 'm', encodes the terminal cells and
  //     recreates the AVL tree proof, and checks that the hash of the resulting AVL digest is equal
  //     to 'm'.
  
  // Vault UTxO registers
  //   R4[Coll[Coll[Byte]]]: The box IDs of UTxOs that contain the committee public keys
  val committeeBoxIDs = INPUTS(0).R4[Coll[Coll[Byte]]].get

  // ===== Data inputs =====
  // Registers of dataInput(0), ..., dataInput(D):
  //   R4[Coll[GroupElement]]: Public keys of committee members
  //   R5[Int]: Index of committee data input. Note that it's not necessary to use this for validation here.
  //
  // Extra registers in dataInput(0):
  //   R6[Coll[Int]]: Vault parameters
  //     0: The number of UTXOs 'D' to store committee information.
  //     1: Current epoch number E >= 1.
  //     2: Epoch length as measured by number of blocks.
  //     3: Starting block height of the Vault 
  //   R7[GroupElement]: Generator of the secp256k1 curve.
  //   R8[GroupElement]: Identity element of secp256k1.
  //   R9[Coll[Byte]]: Byte representation of H(X_1, ..., X_n)
  //

  val vaultParameters = CONTEXT.dataInputs(0).R6[Coll[Int]].get
  val numberCommitteeDataInputBoxes = vaultParameters(0)
  val currentEpoch = vaultParameters(1)
  val epochLength = vaultParameters(2)
  val vaultStart = vaultParameters(3)

  // Verify epoch
  val epochEnd   = vaultStart + currentEpoch * epochLength
  val epochStart = vaultStart + (currentEpoch - 1) * epochLength
  val verifyEpoch = HEIGHT >= epochStart && HEIGHT < epochEnd

  val groupGenerator       = CONTEXT.dataInputs(0).R7[GroupElement].get
  val groupElementIdentity = CONTEXT.dataInputs(0).R8[GroupElement].get
  val innerBytes           = CONTEXT.dataInputs(0).R9[Coll[Byte]].get

  // The GroupElements of each committee member are arranged within a Coll[GroupElement]
  // residing within the R4 register of the first 'D == numberCommitteeDataInputBoxes'
  // data inputs.
  val committee = CONTEXT.dataInputs.slice(0, numberCommitteeDataInputBoxes).fold(
    Coll[GroupElement](),
    { (acc: Coll[GroupElement], x: Box) =>
        acc.append(x.R4[Coll[GroupElement]].get)
    }
  )

  // ContextExtension constants (why the strange ordering of indexes? Bug with recent version of
  // sigmastate-interpreter. See: https://discord.com/channels/668903786361651200/669989266478202917/1177254194021945395):
  //  0: Data to verify the signatures within the exclusion set
  //  5: Aggregate response 'z' from WP.
  //  1: Aggregate commitment 'Y' from WP.
  //  6: Message digest 'm' from WP.
  //  9: Verification threshold
  //  2: Terminal cells describing withdrawals from spectrum-network
  //  7: Starting AVL tree that is used in report notarization
  //  3: AVL tree proof, used to reconstruct part of the tree
  //  8: Maximum miner fee
  val verificationData     = getVar[Coll[((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])) )]](0).get
  val aggregateResponseRaw = getVar[(Coll[Byte], Int)](5).get
  val aggregateCommitment  = getVar[GroupElement](1).get
  val message              = getVar[Coll[Byte]](6).get
  val threshold            = getVar[Int](9).get
  val terminalCells        = getVar[Coll[(Long, (Coll[Byte], Coll[(Coll[Byte], Long)]))]](2).get
  val tree        = getVar[AvlTree](7).get
  val proof       = getVar[Coll[Byte]](3).get
  val maxMinerFee = getVar[Long](8).get

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

  // Computes a_i = H(H(X_1, X_2,.., X_n); X_i)
  def calcA(e: (Coll[GroupElement], Int)) : (Coll[Byte], Int) = {
    val committeeMembers = e._1
    val i = e._2
    val raw = blake2b256(innerBytes.append(committeeMembers(i).getEncoded))
    val split = raw.size - 16
    val firstInt = toSignedBytes(raw.slice(0, split))
    val concatBytes = firstInt.append(toSignedBytes(raw.slice(split, raw.size)))
    val firstIntNumBytes = firstInt.size
    (concatBytes, firstIntNumBytes)
  }
  
  // Computes X~ = X_0^{a_0} * X_1^{a_1} * ... * X_{n-1}^{a_{n-1}}
  def calcFullAggregateKey(e: (Coll[GroupElement], Coll[(Coll[Byte], Int)] )) : GroupElement = {
    val committeeMembers = e._1
    val aiValues = e._2
    committeeMembers.fold(
      (groupElementIdentity, 0),
      { (acc: (GroupElement, Int ), x: GroupElement) =>
          val x_acc = acc._1
          val i = acc._2
          (x_acc.multiply(myExp((x, aiValues(i)))), i + 1)
      }
    )._1
  }

  // Computes X'
  def calcPartialAggregateKey(e: ((Coll[GroupElement], Coll[Int]), Coll[(Coll[Byte], Int)])) : GroupElement = {
    val committeeMembers = e._1._1
    val excludedIndices = e._1._2
    val aiValues = e._2
    committeeMembers.fold(
      (groupElementIdentity, 0),
      { (acc: (GroupElement, Int), x: GroupElement) =>
          val xAcc = acc._1
          val i = acc._2
          if (excludedIndices.exists { (ix: Int) => ix == i }) {
             (xAcc, i + 1)
          } else {
            (xAcc.multiply(myExp((x, aiValues(i)))), i + 1)
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
  
  // Precompute a_i values
  val aiValues = committee.indices.map { (ix: Int) =>
    calcA((committee, ix))
  }

  // c
  val challengeRaw = blake2b256(calcFullAggregateKey((committee, aiValues)).getEncoded ++ aggregateCommitment.getEncoded ++ message )
  val challenge    = encodeUnsigned256BitInt(challengeRaw)

  val excludedIndices = verificationData.map { (e: ((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])))) =>
    e._1._1 
  }

  val excludedCommitments = verificationData.map { (e: ((Int, (GroupElement, Coll[Byte])), ((Coll[Byte], Int), (GroupElement, Coll[Byte])))) =>
    e._1._2._1 
  }

  // Y' from WP
  val YDash = calcAggregateCommitment(excludedCommitments)

  // X' from WP
  val partialAggregateKey = calcPartialAggregateKey(((committee, excludedIndices), aiValues))

  // Verifies that
  //   Y'*g^z == (X')^c * Y
  // which is equivalent to the condition
  //   g^z  == (X')^c * Y * (Y')^(-1)
  // as specified in WP.
  val verifyAggregateResponse = ( myExp((groupGenerator, aggregateResponseRaw)).multiply(YDash) 
      == myExp((partialAggregateKey, challenge)).multiply(aggregateCommitment) )

  // Verifies each taproot signature in the exclusion set
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

  // Check threshold condition from WP
  val verifyThreshold = (committee.size - verificationData.size) >= threshold

  // Check that the address, nano-Erg value and tokens (if they exist) specified in each terminal cell T_i
  // are properly specified in the i'th output box 
  val verifyTxOutputs = terminalCells.zip(OUTPUTS.slice(2, OUTPUTS.size)).forall { (e: ((Long, (Coll[Byte], Coll[(Coll[Byte], Long)])), Box)) => 
    val termCell = e._1
    val outputBox = e._2
    val termCellTokens: Coll[(Coll[Byte], Long)] = termCell._2._2
    outputBox.value == termCell._1 &&
    outputBox.propositionBytes == termCell._2._1 &&
    outputBox.tokens.size == termCell._2._2.size &&
    outputBox.tokens.zip(termCellTokens).forall { (e: ((Coll[Byte], Long), (Coll[Byte], Long))) =>
      e._1 == e._2      
    }
  }

  def hashTerminalCell(cell: (Long, (Coll[Byte], Coll[(Coll[Byte], Long)]))) : Coll[Byte] = {
    val nanoErgs = cell._1
    val propBytes = cell._2._1
    val tokens = cell._2._2
    val tokenBytes = tokens.fold(
      Coll[Byte](),
      { (acc: Coll[Byte], t: (Coll[Byte], Long)) =>
          acc ++ t._1 ++ longToByteArray(t._2)
      }      
    )
    val bytes = longToByteArray(nanoErgs) ++ propBytes ++ tokenBytes
    blake2b256(bytes)
  }

  val verifyAtLeastOneWithdrawal = terminalCells.size > 0

  // Encode each terminal cell into a key-value pair for an AVL insertion operation.  
  val operations = terminalCells.zip(terminalCells.indices).map {
    (e: ((Long, (Coll[Byte], Coll[(Coll[Byte], Long)])), Int) ) =>
      val terminalCell = e._1
      val ix = e._2 + 1
      val key = longToByteArray(ix.toLong)
      val value = hashTerminalCell(terminalCell)
      (key, value)
  }

  // maxMinerFee is also made to be an AVL insertion
  val maxMinerFeeKey = longToByteArray(operations.size.toLong + 1L)
  val maxMinerFeeBytes = longToByteArray(maxMinerFee)
  
  // Need to pad value to 32 bytes, since AVL trees expect constant lengths for keys and values.
  val paddedValue = maxMinerFeeBytes.append(Coll(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).map { (x:Int) => x.toByte })
  val avlInsertions = operations.append(Coll((maxMinerFeeKey, paddedValue))) 

  val endTree = tree.insert(avlInsertions, proof).get
  val verifyDigest = blake2b256(endTree.digest) == message

  val minerPropBytes = fromBase58("2iHkR7CWvD1R4j1yZg5bkeDRQavjAaVPeTDFGGLZduHyfWMuYpmhHocX8GJoaieTx78FntzJbCBVL6rf96ocJoZdmWBL2fci7NqWgAirppPQmZ7fN9V6z13Ay6brPriBKYqLp1bT2Fk4FkFLCfdPpe")
  val validMinerFee = OUTPUTS
        .map { (o: Box) =>
          if (o.propositionBytes == minerPropBytes) o.value else 0L
        }
        .fold(0L, { (a: Long, b: Long) => a + b }) <= maxMinerFee

  val scriptPreserved = OUTPUTS(0).propositionBytes == SELF.propositionBytes

  val verifyCommitteeBoxes = CONTEXT.dataInputs.zip(committeeBoxIDs).forall { (tup: (Box, Coll[Byte])) =>
    val dataInput = tup._1
    val expectedBoxID = tup._2
    dataInput.id == expectedBoxID
  }

  sigmaProp (
    verifyEpoch &&
    verifyAtLeastOneWithdrawal &&
    verifyDigest &&
    verifyAggregateResponse &&
    verifySignaturesInExclusionSet &&
    verifyThreshold &&
    verifyTxOutputs &&
    verifyCommitteeBoxes &&
    validMinerFee &&
    scriptPreserved
  )
}