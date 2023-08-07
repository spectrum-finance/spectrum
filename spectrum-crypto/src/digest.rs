//! Digest types for various sizes
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::hash::{Hash, Hasher};

use blake2::Blake2b;
use digest::consts::U32;
use digest::generic_array::sequence::GenericSequence;
use digest::generic_array::{ArrayLength, GenericArray};
use digest::typenum::Unsigned;
use digest::{FixedOutput, HashMarker, OutputSizeUser, Update};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub type Blake2b256 = Blake2b<U32>;

pub type Blake2bDigest256 = Digest<Blake2b<U32>>;

pub type Sha2Digest256 = Digest<Sha256>;

#[repr(transparent)]
#[derive(Serialize, Deserialize, derive_more::From)]
pub struct Digest<HF: FixedOutput>(GenericArray<u8, HF::OutputSize>);

impl<HF: FixedOutput> Hash for Digest<HF> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<HF: FixedOutput> Ord for Digest<HF> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<HF: FixedOutput> PartialOrd for Digest<HF> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<HF: FixedOutput> PartialEq for Digest<HF> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<HF: FixedOutput> Eq for Digest<HF> {}

impl<HF: FixedOutput> Clone for Digest<HF> {
    fn clone(&self) -> Self {
        Digest(self.0.clone())
    }
}

impl<HF: FixedOutput> Copy for Digest<HF>
where
    HF::OutputSize: ArrayLength<u8>,
    <HF::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<HF: FixedOutput<OutputSize = U32>> Digest<HF> {
    pub const fn zero() -> Self {
        let bytes = [0u8; 32];
        Digest(unsafe { *(bytes.as_ptr() as *const GenericArray<u8, U32>) })
    }
}

impl<HF: FixedOutput> Digest<HF> {
    pub const SIZE: usize = HF::OutputSize::USIZE;

    pub fn from_base16(s: &str) -> Result<Self, DigestNError> {
        let bytes = base16::decode(s)?;
        match GenericArray::from_exact_iter(bytes) {
            Some(arr) => Ok(Digest(arr)),
            None => Err(DigestNError::InvalidSize()),
        }
    }
}

impl<HF: FixedOutput<OutputSize = U32>> Digest<HF> {
    pub fn random() -> Self {
        let mut bf = [0u8; 32];
        thread_rng().fill_bytes(&mut bf);
        Digest(bf.into())
    }
}

impl<HF: FixedOutput> std::fmt::Debug for Digest<HF> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

impl<HF: FixedOutput> std::fmt::Display for Digest<HF> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

pub fn hash<H>(bytes: &[u8]) -> Digest<H>
where
    H: HashMarker + FixedOutput + Default + Update,
{
    use digest::Digest;
    let mut hasher = H::new();
    hasher.update(bytes);
    crate::digest::Digest::from(hasher.finalize_fixed())
}

/// Blake2b256 hash (256 bit)
pub fn blake2b256_hash(bytes: &[u8]) -> Blake2bDigest256 {
    hash(bytes)
}

/// Sha256 hash (256 bit)
pub fn sha256_hash(bytes: &[u8]) -> Sha2Digest256 {
    hash(bytes)
}

impl<HF: FixedOutput> From<Digest<HF>> for Vec<u8> {
    fn from(v: Digest<HF>) -> Self {
        v.0.to_vec()
    }
}

impl<HF: FixedOutput> From<Digest<HF>> for String {
    fn from(v: Digest<HF>) -> Self {
        base16::encode_lower(&v.0.as_ref())
    }
}

impl<HF: FixedOutput> TryFrom<String> for Digest<HF> {
    type Error = DigestNError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base16::decode(&value)?;
        match GenericArray::from_exact_iter(bytes) {
            Some(arr) => Ok(Digest(arr)),
            None => Err(DigestNError::InvalidSize()),
        }
    }
}

impl<HF: FixedOutput> TryFrom<Vec<u8>> for Digest<HF> {
    type Error = DigestNError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match GenericArray::from_exact_iter(value) {
            Some(arr) => Ok(Digest(arr)),
            None => Err(DigestNError::InvalidSize()),
        }
    }
}

impl<HF: FixedOutput> AsRef<[u8]> for Digest<HF> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Invalid byte array size
#[derive(Error, Debug)]
pub enum DigestNError {
    /// error decoding from Base16
    #[error("error decoding from Base16: {0}")]
    Base16DecodingError(#[from] base16::DecodeError),
    /// Invalid byte array size
    #[error("Invalid byte array size")]
    InvalidSize(),
}

/// Arbitrary
#[allow(clippy::unwrap_used)]
#[cfg(feature = "arbitrary")]
pub(crate) mod arbitrary {
    use std::convert::TryInto;

    use proptest::prelude::{Arbitrary, BoxedStrategy};
    use proptest::{collection::vec, prelude::*};

    use super::Digest;

    impl<const N: usize> Arbitrary for Digest<N> {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            vec(any::<u8>(), Self::SIZE)
                .prop_map(|v| Digest(v.try_into().unwrap()))
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_base16() {
        let s = "769a48bdb72d0f7bade76a120982b6d479fda6084c84d40957ae9f935f3b99ac";
        assert!(Blake2bDigest256::from_base16(s).is_ok());
    }

    #[test]
    fn is_copy() {
        let s = "769a48bdb72d0f7bade76a120982b6d479fda6084c84d40957ae9f935f3b99ac";
        let hs = Blake2bDigest256::from_base16(s).unwrap();
        let _hs2 = hs;
        let _hs3 = hs;
    }
}
