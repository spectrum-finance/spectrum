# ECVRF

The Elliptic Curve Verifiable Random Function is a Verifiable Random Function (VRF) that
satisfies the trusted uniqueness, trusted collision resistance, and full pseudorandomness properties. The security
of this ECVRF follows from the decisional Diffie-Hellman (DDH) assumption in the random oracle model.

* [905.pdf](https://eprint.iacr.org/2014/905.pdf)
* [1045.pdf](https://eprint.iacr.org/2022/1045.pdf)

# Lottery
todo

# Data required in the BlockHeader

Each block must include the following fields with the VRF proofs, included by the leader proposed the block.
| Header | Type |
| ------------- | ------------- |
| `Proof`  | `(ProjectivePoint, Scalar, Scalar)`  |