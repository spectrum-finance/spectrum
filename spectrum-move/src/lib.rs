pub mod execution;

#[derive(Eq, PartialEq, Clone, Debug, derive_more::From, derive_more::Into, serde::Serialize, serde::Deserialize)]
pub struct SerializedModule(Vec<u8>);

#[derive(Eq, PartialEq, Clone, Debug, derive_more::From, derive_more::Into, serde::Serialize, serde::Deserialize)]
pub struct SerializedValue(Vec<u8>);

#[derive(Eq, PartialEq, Copy, Clone, derive_more::Add, derive_more::Sub, Debug, serde::Serialize, serde::Deserialize)]
pub struct GasUnits(u64);

impl GasUnits {
    pub const ZERO: GasUnits = GasUnits(0);
}
