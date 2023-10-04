# Ergo Vault documentation

The Spectrum Vault on the Ergo blockchain is a collection $\mathcal{V}$ of
UTXOs that are guarded by a smart contract that can:
 - Perform $\text{verify}(\sigma, \alpha PK, m)$, where $\sigma$ denotes a
   signature of a message $m$ that was signed by an aggregated public key
   $\alpha PK$ of the current committee.
 - Verifies that the associated committee is still valid for the current block
   height.
 - Use $m$ together with ancillary data to perform a proof that a collection of
   withdrawals from $\mathcal{V}$ was notarized by Spectrum Network consensus.

A Vault-manager is responsible for assembling and submitting transactions to
perform these withdrawals.

## On-chain read-only elements

The current committee public keys reside in register R4 of each UTXO in
$\mathcal{C} = \{C_0, \dots, C_{D-1}\}$. These UTXOs are ordered and indexed by
an `Int` that resides in register R5. $\mathcal{C}$ is supplied to the guarding
contract as data inputs.

In addition the first data input $C_0$ contains other data necessary for
validation. This data is constant for the duration of its associated epoch and
they reside in the following registers:
 - R6[Coll[Int]]: Vault parameters
     - 0: The number of UTXOs $D$ to store committee information.
     - 1: Current epoch number $E \ge 1$.
     - 2: Epoch length as measured by number of blocks.
     - 3: Starting block height of the Vault 
 - R7[GroupElement]: The generator of the secp256k1 curve.
 - R8[GroupElement]: The identity element of secp256k1.
 - R9[Coll[Byte]]: The value of $H(X_0, \dots, X_n)$, where $X_i$ represents
   the public key of the i'th committee member.

## Context extension

When creating the transaction, the vault-manager stores all other data within
the context-extension such as the message digest $m$, details of withdrawals,
proofs of notarization and other information to verify the aggregated signature
of the current committee.

## Proof of withdrawal notarization with AVL trees

We use AVL trees - a data structure that is built-in to Ergoscript - to verify
that withdrawals were notarized by spectrum-consensus. Suppose that there are
$n_w$ withdrawals $\mathcal{W} = \{W_0, W_1, \dots, W_{n_w}\}$, each to
distinct adresses on the Ergo chain. These withdrawals are assembled by the
slot leader of the committee. Each withdrawal $W_i$ corresponds to a key-value
pair $(i, H(W_i))$ where $H(W_i)$ is a Blake2b256 hash of a serialized
representation of $W_i$.

Starting with an empty AVL tree, we insert in order: $(0,H(W_0)), (1,
H(W_1))\dots, (n_w, H(W_{n_w}))$. We set $m$ to be the resulting AVL tree
digest, and it is this value that will be signed by the aggregated key of the
current committee.

Now $\mathcal{W}$, $m$ and the AVL tree proof will be passed to the contract
via context-extension variables, where the same key-value pairs are computed
and inserted into the tree. If the resulting AVL tree digest equals $m$, we
have proved notarization of the withdrawals.


## Exponentiation of elliptic curve points and limitations of Ergoscript

A limitation of Ergoscript is that only signed integers are supported, the
largest of which is `BigInt` - a signed 256bit integer type. This is problematic
for our on-chain verification of aggregated signatures, as we need to compute
  $X^a$, where $X$ is a point on the secp256k1 curve and $a$ is an *unsigned*
  256bit integer.

We can work around this limitation by decomposing the unsigned int $a$ as
follows. Let $B(a)$ denote the big-endian byte representation of $a$. Note that
it has a maximal length of 32 bytes and will be less than 32 for smaller
integer values. Let $s = \text{length}(B(a)) - 16$, and define

 - $B_L(a) = B(a)[s..]$, the *last* 16 bytes of $B(a)$. Let this be the byte
   representation of an unsigned integer $L$.
 - $B_U(a) = B(a)[..s]$ all bytes from index 0 up to but not including $s$, representing
 an unsigned integer $U$.
 
Now $a = U *p + L$, where $p = 340282366920938463463374607431768211456$.
Crucially, the signed integer representation of $U$, $L$ and $p$ can fit within
256bits. Sending the byte-representation of **signed** integer forms for $U$, $L$
and $p$, we can compute $X^a$ in Ergoscript as

$$ X^a = X^{U*p + L} = (X^U)^pX^L$$

Every exponentiation on the right-hand side can be computed in Ergoscript as
long as $U$, $L$ and $p$ are represented as `BigInt`.

