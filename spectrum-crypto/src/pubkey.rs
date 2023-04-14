use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Formatter;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// N-bytes array in a box. Usually a hash.`Digest32` is most type synonym.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, Serialize, Deserialize)]
#[serde(into = "Vec<u8>", try_from = "Vec<u8>")]
pub struct PubKeyBytes<const N: usize>(pub [u8; N]);

pub type PubKeyBytes32 = PubKeyBytes<32>;

impl<const N: usize> PubKeyBytes<N> {
    /// Digest size 32 bytes
    pub const SIZE: usize = N;

    /// All zeros
    pub fn zero() -> PubKeyBytes<N> {
        PubKeyBytes([0u8; N])
    }

    pub fn from_base16(s: &str) -> Result<PubKeyBytes<N>, DigestNError> {
        let bytes = base16::decode(s)?;
        let arr: [u8; N] = bytes.as_slice().try_into()?;
        Ok(PubKeyBytes(arr))
    }
}

impl<const N: usize> std::fmt::Debug for PubKeyBytes<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

impl<const N: usize> std::fmt::Display for PubKeyBytes<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        base16::encode_lower(&(self.0)).fmt(f)
    }
}

/// Blake2b256 hash (256 bit)
pub fn blake2b256_hash(bytes: &[u8]) -> PubKeyBytes32 {
    PubKeyBytes(*crate::hash::blake2b256_hash(bytes))
}

impl<const N: usize> From<[u8; N]> for PubKeyBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        PubKeyBytes(bytes)
    }
}

impl<const N: usize> From<Box<[u8; N]>> for PubKeyBytes<N> {
    fn from(bytes: Box<[u8; N]>) -> Self {
        PubKeyBytes(*bytes)
    }
}

impl<const N: usize> From<PubKeyBytes<N>> for Vec<u8> {
    fn from(v: PubKeyBytes<N>) -> Self {
        v.0.to_vec()
    }
}

impl<const N: usize> From<PubKeyBytes<N>> for [u8; N] {
    fn from(v: PubKeyBytes<N>) -> Self {
        v.0
    }
}

impl<const N: usize> From<PubKeyBytes<N>> for String {
    fn from(v: PubKeyBytes<N>) -> Self {
        base16::encode_lower(&v.0.as_ref())
    }
}

impl<const N: usize> TryFrom<String> for PubKeyBytes<N> {
    type Error = DigestNError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = base16::decode(&value)?;
        let arr: [u8; N] = bytes.as_slice().try_into()?;
        Ok(PubKeyBytes(arr))
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for PubKeyBytes<N> {
    type Error = DigestNError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: [u8; N] = value.as_slice().try_into()?;
        Ok(PubKeyBytes::from(bytes))
    }
}

impl<const N: usize> TryFrom<&[u8]> for PubKeyBytes<N> {
    type Error = DigestNError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; N] = value.try_into()?;
        Ok(PubKeyBytes::from(bytes))
    }
}

impl AsRef<[u8]> for PubKeyBytes32 {
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

    use super::PubKeyBytes;

    impl<const N: usize> Arbitrary for PubKeyBytes<N> {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            vec(any::<u8>(), Self::SIZE)
                .prop_map(|v| PubKeyBytes(v.try_into().unwrap()))
                .boxed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_base64() {
        let s = "769a48bdb72d0f7bade76a120982b6d479fda6084c84d40957ae9f935f3b99ac=";
        assert!(PubKeyBytes32::from_base16(s).is_ok());
    }
}
