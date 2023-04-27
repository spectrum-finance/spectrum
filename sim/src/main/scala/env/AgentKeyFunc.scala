package env

// Data necessary to fully identify participant of the protocol ("Account" owner):
case class Address(value: String)

case class VrfSecretKey(value: String)
case class VrfPublicKey(value: String)
case class VrfProof(value: String)

case class KesSecretKey(value: String)
case class KesPublicKey(value: String)
case class KesSignature(value: String)

case class DsigSecretKey(value: String)
case class DsigPublicKey(value: String)
case class DsigSignature(value: String)

case class Account(
    address: Address,
    stake: Long,
    vrfPk: VrfPublicKey,
    kesPk: KesPublicKey,
    dsigPk: DsigPublicKey
)

// Requests to and Responses from the Key functions:
case class VrfGenRequest(sessionId: Int)
case class VrfGenResponse(vrf: VRF, sessionId: Int, sk: VrfSecretKey, pk: VrfPublicKey)
case class VrfEvalRequest(
    sessionId: Int,
    epochSeed: String,
    slot: Long,
    additionalString: String,
    vrfPk: VrfPublicKey
)
case class VrfEvalResponse(vrf: VRF, sessionId: Int, y: String, proof: VrfProof)
case class VrfVerifyRequest(
    sessionId: Int,
    epochSeed: String,
    slot: Long,
    additionalString: String,
    y: String,
    proof: VrfProof,
    vrfPk: VrfPublicKey
)
case class VrfVerifyResponse(
    sessionId: Int,
    y: String,
    proof: VrfProof,
    vrfPk: VrfPublicKey,
    isValid: Boolean
)

// Key functions (VRF, KES, DSIG)
case class VRF(
    address: Address,
    sk: VrfSecretKey = VrfSecretKey(""),
    pk: VrfPublicKey = VrfPublicKey(""),
    table: Map[Address, Map[VrfPublicKey, Map[String, String]]]
): // Verifiable Random Function
  def gen(request: VrfGenRequest): VrfGenResponse =
    val sk = VrfSecretKey(Utility.generateRandomKey())
    val pk = VrfPublicKey(Utility.getHash(v = sk.value))
    VrfGenResponse(
      vrf = copy(
        address = address,
        sk = sk,
        pk = pk,
        table = table.concat(Map(address -> Map(pk -> Map("" -> ""))))
      ),
      sessionId = request.sessionId,
      sk = sk,
      pk = pk
    )

  def eval(
      request: VrfEvalRequest
  ): VrfEvalResponse =
    val m =
      Seq(request.vrfPk.value, request.epochSeed, request.slot.toString, request.additionalString)
        .mkString("")
    val y     = Utility.getHash(m)
    val proof = Utility.getHash(Seq(request.vrfPk.value, y).mkString(""))
    VrfEvalResponse(
      vrf = copy(
        table = table.concat(Map(address -> Map(pk -> Map(m -> y))))
      ),
      sessionId = request.sessionId,
      y = y,
      proof = VrfProof(value = proof)
    )

  def verify(
      request: VrfVerifyRequest
  ): VrfVerifyResponse =

    val valid = request.proof.value == Utility.getHash(
      request.vrfPk.value + Utility.getHash(
        Seq(
          request.vrfPk.value,
          request.epochSeed,
          request.slot.toString,
          request.additionalString
        ).mkString("")
      )
    ) && request.proof.value == Utility.getHash(Seq(request.vrfPk.value, request.y).mkString(""))
    // TODO: check correctness of the "table"

    VrfVerifyResponse(
      sessionId = request.sessionId,
      y = request.y,
      proof = request.proof,
      vrfPk = request.vrfPk,
      isValid = valid
    )

case class KesGenRequest(sessionId: Int, address: Address)
case class KesGenResponse(kes: KES, sessionId: Int, pk: KesPublicKey)
case class KesSignRequest(
    sessionId: Int,
    address: Address,
    block: Block,
    slot: Long
)
case class KesSignResponse(
    kes: KES,
    sessionId: Int,
    address: Address,
    signedBlock: Block,
    slot: Long
)
case class KesVerifyRequest(
    sessionId: Int,
    signedBlock: Block,
    slot: Long,
    pk: KesPublicKey
)
case class KesVerifyResponse(
    sessionId: Int,
    signedBlock: Block,
    slot: Long,
    isValid: Boolean
)

case class DsigGenRequest(sessionId: Int, address: Address)
case class DsigGenResponse(dsig: DSIG, sessionId: Int, pk: DsigPublicKey)
case class DsigSignRequest(
    sessionId: Int,
    address: Address,
    tx: Transaction
)
case class DsigSignResponse(
    sessionId: Int,
    signedTx: Transaction
)
case class DsigVerifyRequest(
    sessionId: Int,
    signedTx: Transaction,
    pk: DsigPublicKey
)
case class DsigVerifyResponse(
    sessionId: Int,
    signedTx: Transaction,
    isValid: Boolean
)
case class KES(
    address: Address,
    sk: KesSecretKey = KesSecretKey(""),
    pk: KesPublicKey = KesPublicKey(""),
    table: Map[Address, Map[Long, KesPublicKey]]
): // Key Evolving Signature
  def gen(request: KesGenRequest): KesGenResponse =
    val kesSk = Utility.generateRandomKey()
    val kesPk = Utility.getHash(v = kesSk)
    KesGenResponse(
      copy(address = address),
      sessionId = request.sessionId,
      pk = KesPublicKey(value = kesPk)
    )

  def sign(request: KesSignRequest): KesSignResponse =
    val sign = KesSignature(
      Utility.getHash(Seq(request.block.data.toString, request.slot, pk).mkString(""))
    )
    KesSignResponse(
      copy(address = address),
      sessionId = request.sessionId,
      address = request.address,
      signedBlock = request.block.copy(leaderSignature = sign),
      slot = request.slot
    )

  // TODO: def update(x: Long):

  def verify(request: KesVerifyRequest): KesVerifyResponse =
    val sign =
      Utility.getHash(Seq(request.signedBlock.data.toString, request.slot, request.pk).mkString(""))

    val valid = sign == request.signedBlock.leaderSignature.value
    KesVerifyResponse(
      sessionId = request.sessionId,
      signedBlock = request.signedBlock,
      slot = request.slot,
      isValid = valid
    )

case class DSIG(
    address: Address,
    sk: DsigSecretKey = DsigSecretKey(""),
    pk: DsigPublicKey = DsigPublicKey(""),
    table: Map[Address, DsigPublicKey]
): // Digital Signature
  // TODO: add sid to tables:
  def gen(request: DsigGenRequest): DsigGenResponse =
    val dsigSk = DsigSecretKey(Utility.generateRandomKey())
    val dsigPk = DsigPublicKey(Utility.getHash(v = dsigSk.value))
    DsigGenResponse(copy(pk = dsigPk, sk = dsigSk), sessionId = request.sessionId, pk = dsigPk)

  def sign(request: DsigSignRequest): DsigSignResponse =
    val sig = DsigSignature(Utility.getHash(request.tx.data.toString + pk))
    DsigSignResponse(sessionId = request.sessionId, signedTx = request.tx.copy(sig = sig))

  def verify(request: DsigVerifyRequest): DsigVerifyResponse =
    val valid =
      request.signedTx.sig.value == Utility.getHash(request.signedTx.data.toString + request.pk)
    DsigVerifyResponse(sessionId = request.sessionId, signedTx = request.signedTx, isValid = valid)
