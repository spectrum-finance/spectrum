use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use serde::ser::SerializeTupleStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

/// Something that is represented as an `ErgoBox` on-chain.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AsBox<T>(pub ErgoBox, pub T);

impl<T> Hash for AsBox<T>
where
    T: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0.sigma_serialize_bytes().unwrap());
        self.1.hash(state);
    }
}

impl<T> Serialize for AsBox<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut serde_state = match serializer.serialize_tuple_struct("AsBox", 2usize) {
            Ok(val) => val,
            Err(err) => {
                return Err(err);
            }
        };
        match serde_state.serialize_field(&self.0.sigma_serialize_bytes().unwrap()) {
            Ok(val) => val,
            Err(err) => {
                return Err(err);
            }
        };
        match serde_state.serialize_field(&self.1) {
            Ok(val) => val,
            Err(err) => {
                return Err(err);
            }
        };
        serde_state.end()
    }
}

impl<'de, T> Deserialize<'de> for AsBox<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor<'de, T>
        where
            T: Deserialize<'de>,
        {
            marker: PhantomData<AsBox<T>>,
            lifetime: PhantomData<&'de ()>,
        }
        impl<'de, T> de::Visitor<'de> for Visitor<'de, T>
        where
            T: Deserialize<'de>,
        {
            type Value = AsBox<T>;
            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("tuple struct AsBox")
            }
            #[inline]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let field0 = match match seq.next_element::<Vec<u8>>() {
                    Ok(val) => val,
                    Err(err) => {
                        return Err(err);
                    }
                } {
                    Some(value) => value,
                    None => {
                        return Err(de::Error::invalid_length(
                            0usize,
                            &"tuple struct AsBox with 2 elements",
                        ));
                    }
                };
                let field1 = match match seq.next_element() {
                    Ok(val) => val,
                    Err(err) => {
                        return Err(err);
                    }
                } {
                    Some(value) => value,
                    None => {
                        return Err(de::Error::invalid_length(
                            1usize,
                            &"tuple struct AsBox with 2 elements",
                        ));
                    }
                };
                Ok(AsBox(ErgoBox::sigma_parse_bytes(&field0).unwrap(), field1))
            }
        }
        deserializer.deserialize_tuple_struct(
            "AsBox",
            2usize,
            Visitor {
                marker: PhantomData::<AsBox<T>>,
                lifetime: PhantomData,
            },
        )
    }
}
