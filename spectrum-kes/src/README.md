# Key Evolving Signature (KES)

The Key Evolving Signature mechanism prevents an attacker from generating signatures for
messages that were created in the past. It also allows any protocol
participant to verify that a given signature was generated with the legal signing key for a
particular slot.
The security guarantees are achieved by evolving the secret key after each signature
in a way that the actual secret key was used to sign the previous message
cannot be recovered.

* [2001/034](https://eprint.iacr.org/2001/034)
* [2017/573](https://cseweb.ucsd.edu/~daniele/papers/MMM.pdf)

# Data required in the BlockHeader

Each block must include the leaders' signature.
| Header | Type |
| ------------- | ------------- |
| `Signature`  | `(Signature, PublicKey, Vec\<PublicKey\>)`  |

There are `2^N` Secret Keys that can be securely restored using this scheme. Number of `PublicKeys` that must be stored
in the `Vec\<PublicKey\>` is `N`.