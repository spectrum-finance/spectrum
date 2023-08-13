use std::hash::{Hash, Hasher};

use elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use libp2p_identity::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey(k256::PublicKey);

impl<'a> From<&'a PublicKey> for &'a k256::PublicKey {
    fn from(value: &'a PublicKey) -> Self {
        &value.0
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.0.to_encoded_point(true).as_bytes());
    }
}

impl From<SecretKey> for PublicKey {
    fn from(sk: SecretKey) -> Self {
        Self(sk.public_key())
    }
}

impl From<PublicKey> for k256::PublicKey {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl From<k256::PublicKey> for PublicKey {
    fn from(pk: k256::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PublicKey> for PeerId {
    fn from(pk: PublicKey) -> Self {
        let k256point = pk.0.to_encoded_point(true);
        let encoded_pk = k256point.as_bytes();
        PeerId::from_public_key(&libp2p_identity::PublicKey::from(
            libp2p_identity::secp256k1::PublicKey::try_from_bytes(encoded_pk).unwrap(),
        ))
    }
}

impl From<&PublicKey> for PeerId {
    fn from(pk: &PublicKey) -> Self {
        pk.clone().into()
    }
}
