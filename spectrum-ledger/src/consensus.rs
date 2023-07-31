use std::fmt::{Debug, Formatter};

use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::{Error, ScalarPrimitive};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{EncodedPoint, ProjectivePoint, Secp256k1};

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_crypto::pubkey::PublicKey;
use spectrum_vrf::vrf::ECVRFProof;

use crate::SystemDigest;

#[derive(
    Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct KESVKey(PublicKey);

#[derive(
    Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct VRFVKey(PublicKey);

impl SystemDigest for VRFVKey {
    fn digest(&self) -> Blake2bDigest256 {
        blake2b256_hash(k256::PublicKey::from(vk.0).to_encoded_point(true).as_bytes())
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From)]
pub enum DomainVKey {
    Schnorr(PublicKey),
}

#[derive(
    Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct KESSignature(spectrum_kes::KESSignature<Secp256k1>);

impl Debug for KESSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("sig")
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
#[serde(try_from = "VRFProofRaw", into = "VRFProofRaw")]
pub struct VRFProof(ECVRFProof<Secp256k1>);

#[derive(serde::Serialize, serde::Deserialize)]
struct VRFProofRaw {
    gamma: Vec<u8>,
    c: ScalarPrimitive<Secp256k1>,
    s: ScalarPrimitive<Secp256k1>,
}

impl Into<VRFProofRaw> for VRFProof {
    fn into(self) -> VRFProofRaw {
        VRFProofRaw {
            gamma: self.0.gamma.to_bytes().to_vec(),
            c: self.0.c.into(),
            s: self.0.s.into(),
        }
    }
}

impl TryFrom<VRFProofRaw> for VRFProof {
    type Error = Error;
    fn try_from(value: VRFProofRaw) -> Result<Self, Self::Error> {
        let gamma = EncodedPoint::from_bytes(&*value.gamma)
            .map(|r| ProjectivePoint::from_encoded_point(&r).unwrap())?;
        Ok(VRFProof(ECVRFProof {
            gamma,
            c: value.c.into(),
            s: value.s.into(),
        }))
    }
}

/// Identifier of a stake pool.
/// Derived from the hash of validator VRF vkey.
#[derive(
    Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct StakePoolId(Blake2bDigest256);

impl From<VRFVKey> for StakePoolId {
    fn from(vk: VRFVKey) -> Self {
        Self(vk.digest())
    }
}
