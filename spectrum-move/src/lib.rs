pub mod execution;

#[derive(Eq, PartialEq, Clone, Debug, derive_more::From, derive_more::Into)]
pub struct SerializedModule(Vec<u8>);

#[derive(Eq, PartialEq, Clone, Debug, derive_more::From, derive_more::Into)]
pub struct SerializedValue(Vec<u8>);

#[derive(Eq, PartialEq, Copy, Clone, derive_more::Add, derive_more::Sub, Debug)]
pub struct GasUnits(u64);
