use k256::schnorr::signature::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::Into)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct Signature(k256::schnorr::Signature);

impl From<k256::schnorr::Signature> for Signature {
    fn from(sig: k256::schnorr::Signature) -> Self {
        Self(sig)
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        k256::schnorr::Signature::try_from(&*value).map(Signature)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(Signature(sig): Signature) -> Self {
        <Vec<u8>>::from(sig.to_bytes())
    }
}
