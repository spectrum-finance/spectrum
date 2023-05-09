//! Digest types for various sizes
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Formatter;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

#[derive(Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Hash)]
pub struct Blake2b;

#[derive(Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Hash)]
pub struct Sha2;

/// N-bytes array in a box. Usually a hash.`Digest32` is most type synonym.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(into = "Vec<u8>", try_from = "Vec<u8>")]
pub struct Digest<const N: usize, H>([u8; N], PhantomData<H>);

impl<const N: usize, H> Clone for Digest<N, H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<const N: usize, H> Copy for Digest<N, H> {}

impl<const N: usize, H> Serialize for Digest<N, H> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

pub type Digest256<H> = Digest<32, H>;

pub type Blake2bDigest256 = Digest<32, Blake2b>;

pub type Sha2Digest256 = Digest<32, Sha2>;

impl<const N: usize, H> Digest<N, H> {
    /// Digest size 32 bytes
    pub const SIZE: usize = N;

    /// All zeros
    pub fn zero() -> Digest<N, H> {
        Digest([0u8; N], PhantomData::default())
    }

    pub fn from_base16(s: &str) -> Result<Digest<N, H>, DigestNError> {
        let bytes = base16::decode(s)?;
        let arr: [u8; N] = bytes.as_slice().try_into()?;
        Ok(Digest(arr, PhantomData::default()))
    }
}

impl<const N: usize, H> std::fmt::Debug for Digest<N, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

impl<const N: usize, H> std::fmt::Display for Digest<N, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

/// Blake2b256 hash (256 bit)
pub fn blake2b256_hash(bytes: &[u8]) -> Blake2bDigest256 {
    Digest(*crate::hash::blake2b256_hash(bytes), PhantomData::default())
}

/// Sha256 hash (256 bit)
pub fn sha256_hash(bytes: &[u8]) -> Sha2Digest256 {
    Digest(*crate::hash::sha256_hash(bytes), PhantomData::default())
}

impl<const N: usize, H> From<[u8; N]> for Digest<N, H> {
    fn from(bytes: [u8; N]) -> Self {
        Digest(bytes, PhantomData::default())
    }
}

impl<const N: usize, H> From<Box<[u8; N]>> for Digest<N, H> {
    fn from(bytes: Box<[u8; N]>) -> Self {
        Digest(*bytes, PhantomData::default())
    }
}

impl<const N: usize, H> From<Digest<N, H>> for Vec<u8> {
    fn from(v: Digest<N, H>) -> Self {
        v.0.to_vec()
    }
}

impl<const N: usize, H> From<Digest<N, H>> for [u8; N] {
    fn from(v: Digest<N, H>) -> Self {
        v.0
    }
}

impl<const N: usize, H> From<Digest<N, H>> for String {
    fn from(v: Digest<N, H>) -> Self {
        base16::encode_lower(&v.0.as_ref())
    }
}

impl<const N: usize, H> TryFrom<String> for Digest<N, H> {
    type Error = DigestNError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base16::decode(&value)?;
        let arr: [u8; N] = bytes.as_slice().try_into()?;
        Ok(Digest(arr, PhantomData::default()))
    }
}

impl<const N: usize, H> TryFrom<Vec<u8>> for Digest<N, H> {
    type Error = DigestNError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: [u8; N] = value.as_slice().try_into()?;
        Ok(Digest::from(bytes))
    }
}

impl<const N: usize, H> TryFrom<&[u8]> for Digest<N, H> {
    type Error = DigestNError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; N] = value.try_into()?;
        Ok(Digest::from(bytes))
    }
}

impl<const N: usize, H> AsRef<[u8]> for Digest<N, H> {
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
    #[error("Invalid byte array size ({0})")]
    InvalidSize(#[from] std::array::TryFromSliceError),
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
}
