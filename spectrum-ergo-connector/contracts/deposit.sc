{
  // Validations
  // 1. Deposits are made to the correct Vault UTxO (by checking Vault token);
  // 2. Vault script is preserved
  // 3. Correct Ergs deposited
  // 4. Correct tokens deposited + all existing tokens preserved
  // 5. Address bytes of depositor is present
  
  val maxMinerFee = getVar[Long](8).get
  val expectedVaultTokenId = SELF.R4[Coll[Byte]].get

  // Validate (1) (Note that validation of (4) ensures that the vault token is preserved)
  val validVaultUTxO = expectedVaultTokenId == INPUTS(0).tokens(0)._1

  // Validate (2)
  val scriptPreserved = OUTPUTS(0).propositionBytes == INPUTS(0).propositionBytes

  val minerPropBytes = fromBase16("1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304")
  val minerFee = OUTPUTS
    .map { (o: Box) =>
      if (o.propositionBytes == minerPropBytes) o.value else 0L
    }
    .fold(0L, { (a: Long, b: Long) => a + b })
  val validMinerFee = minerFee <= maxMinerFee

  val deposits = INPUTS.slice(1, INPUTS.size)
  val existingVaultErgBalance = INPUTS(0).value
  val totalErgDepositValue = deposits.fold(0L, { (acc: Long, input: Box) => acc + input.value })

  // Validate (3)
  val validErgDeposits = existingVaultErgBalance + totalErgDepositValue == OUTPUTS(0).value + minerFee

  // This lambda attempts to find a token with specific token ID within 'tokens'. Returns
  // `(index, tokenQty)`, where if `tokenQty == 0`, the token ID we sought doesn't exist.
  // Otherwise `index` represents the index within `tokens` containing the token we're 
  // looking for and `tokenQty` is the quantity of this token.
  //
  // Note: we can't return Option[(Int, Long)] since Ergoscript currently doesn't allow us
  // to create Option[T] literals.
  def findToken(e: (Coll[(Coll[Byte], Long)], Coll[Byte])) : (Int, Long) = {
    val tokens = e._1
    val tokenIdToFind = e._2
    tokens.indices.zip(tokens).fold(
      (0,0L),
      { (acc: (Int, Long), elem: (Int, (Coll[Byte], Long))) =>
        val tokenId = elem._2._1
        val tokenQty = elem._2._2
        val index = elem._1
        if (acc._2 == 0L && tokenId == tokenIdToFind) {
          (index, tokenQty)
        } else {
          acc
        }
      }
    )
  }

  // Similar to `findToken` above, but we iterate through an indexed collection of tokens instead.
  def findTokenInExisting(e: (Coll[(Int, (Coll[Byte], Long))], Coll[Byte])) : (Int, Long) = {
    val indexedTokens = e._1
    val tokenIdToFind = e._2
    indexedTokens.indices.zip(indexedTokens).fold(
      (0,0L),
      { (acc: (Int, Long), elem: (Int, (Int, (Coll[Byte], Long)))) =>
        val tokenId = elem._2._2._1
        val tokenQty = elem._2._2._2
        val index = elem._1
        if (acc._2 == 0L && tokenId == tokenIdToFind) {
          (index, tokenQty)
        } else {
          acc
        }
      }
    )
  }

  // Iterate through all tokens contained in every deposit and compute the tuple:
  //   (existing, new)
  // where:
  //   - `existing` is a collection of tuples `(index, (tokenId, updatedQuantity))`
  //     such that `index` is the location within the Vault UTxO's collection of tokens
  //     containing a token with id `tokenId` and `updatedQuantity` is the resulting
  //     quantity of this token after all deposits of it have been made.
  //   - `new` is a collection of tokens to deposit which do not exist within the input
  //      Vault UTxO.   
  val tokenDiffs = deposits.fold(
    (Coll[(Int, (Coll[Byte], Long))](), Coll[(Coll[Byte], Long)]()),
    { (acc: (Coll[(Int, (Coll[Byte], Long))], Coll[(Coll[Byte], Long)]), input: Box) =>
  
      input.tokens.fold(
        acc,
        {(accInner: (Coll[(Int, (Coll[Byte], Long))], Coll[(Coll[Byte], Long)]), token: (Coll[Byte], Long)) =>
          val existing = accInner._1
          val new = accInner._2
          val tokenId = token._1
          val searchResult = findTokenInExisting((existing, tokenId))
          val index = searchResult._1
          val qty = searchResult._2
          
          // If token already exists within the Vault UTxO and already has a deposit. 
          if (qty > 0L) {
            val vaultIndex = existing(index)._1
            val newElem = (vaultIndex, (tokenId, qty + token._2))
            val newExisting = existing.updated(index, newElem)
            (newExisting, new)
          } else {
            val searchVaultResult = findToken((INPUTS(0).tokens, tokenId))
            val vaultIndex = searchVaultResult._1
            val vaultTokenId = INPUTS(0).tokens(vaultIndex)._1
            val vaultTokenQty = searchVaultResult._2
            
            // Token already exists in the Vault UTxO and this is the first deposit of
            // such a token.
            if (vaultTokenQty > 0L) {
              val newElem = (vaultIndex, (vaultTokenId, vaultTokenQty + token._2))
              val newExisting = existing.append(Coll[(Int, (Coll[Byte], Long))](newElem))
              (newExisting, new)
            } else {
              val searchNewlyAddedResult = findToken((new, tokenId))
              val newlyAddedIndex = searchNewlyAddedResult._1
              val newlyAddedQty = searchNewlyAddedResult._2
              
              // Token doesn't exist in the Vault UTxO but we've already seen a deposit of
              // this deposit already.
              if (newlyAddedQty > 0L) {
                val existingQty = new(newlyAddedIndex)._2
                val updatedNew = new.updated(newlyAddedIndex, (tokenId, existingQty + token._2))
                (existing, updatedNew)
              } else {
                // Token doesn't belong int the Vault UTxO and this is the first deposit witnessed.
                val updatedNew = new.append(Coll[(Coll[Byte], Long)]((tokenId, token._2)))
                (existing, updatedNew)
              }
            }    
          }
        }
      )
    }
  )

  val existing = tokenDiffs._1
  val newTokens = tokenDiffs._2

  // Take the input Vault UTxO's set of tokens and update the quantities after deposits
  // are made.
  val updatedWithExisting = existing.fold(
    INPUTS(0).tokens,
    { (acc: Coll[(Coll[Byte], Long)], elem: (Int, (Coll[Byte], Long))) =>
      val index = elem._1
      val tokenId = elem._2._1
      val tokenQty = elem._2._2

      acc.updated(index, (tokenId, tokenQty))
    }
  )

  val vaultTokensAfterDeposits = updatedWithExisting.append(newTokens)
  
  // Validate (4)
  val validTokenDeposits = vaultTokensAfterDeposits == OUTPUTS(0).tokens

  // Validate (5)
  val depositorAddressPresent = !(SELF.R5[Coll[Byte]].isEmpty)


  sigmaProp(
    validVaultUTxO &&
    scriptPreserved &&
    validMinerFee &&
    validErgDeposits &&
    validTokenDeposits &&
    depositorAddressPresent
  )
}