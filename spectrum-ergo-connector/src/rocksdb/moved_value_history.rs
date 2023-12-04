use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{MovedValue, UserValue};

use crate::script::{ErgoInboundCell, ErgoTermCell};

#[async_trait(?Send)]
pub trait MovedValueHistory {
    async fn append(&mut self, moved_value: ErgoMovedValue);
    /// Returns ErgoMovedValue that is closest and >= `height`.
    async fn get(&self, height: u32) -> Option<(ErgoMovedValue, u32)>;
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct ErgoUserValue {
    /// Value that is inbound to Spectrum-network
    pub imported_value: Vec<ErgoInboundCell>,
    /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
    pub exported_value: Vec<ErgoTermCell>,
    pub progress_point: u32,
}

impl From<ErgoUserValue> for UserValue {
    fn from(value: ErgoUserValue) -> Self {
        todo!()
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoMovedValue {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(ErgoUserValue),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(ErgoUserValue),
}

impl ErgoMovedValue {
    pub fn get_height(&self) -> u32 {
        match self {
            ErgoMovedValue::Applied(user_value) | ErgoMovedValue::Unapplied(user_value) => {
                user_value.progress_point
            }
        }
    }

    pub fn get_user_value(&self) -> ErgoUserValue {
        match self {
            ErgoMovedValue::Applied(mv) | ErgoMovedValue::Unapplied(mv) => mv.clone(),
        }
    }
}

impl From<ErgoMovedValue> for MovedValue {
    fn from(value: ErgoMovedValue) -> Self {
        let user_value = UserValue::from(value.get_user_value());
        match value {
            ErgoMovedValue::Applied(_) => MovedValue::Applied(user_value),
            ErgoMovedValue::Unapplied(_) => MovedValue::Unapplied(user_value),
        }
    }
}

pub struct InMemoryMovedValueHistory {
    history: Vec<ErgoMovedValue>,
}

impl InMemoryMovedValueHistory {
    pub fn new() -> Self {
        Self { history: vec![] }
    }
}

#[async_trait(?Send)]
impl MovedValueHistory for InMemoryMovedValueHistory {
    async fn append(&mut self, moved_value: ErgoMovedValue) {
        self.history.push(moved_value);
    }

    async fn get(&self, height: u32) -> Option<(ErgoMovedValue, u32)> {
        let mut prev = None;
        for moved_value in &self.history {
            let next_height = moved_value.get_height();
            if prev.is_none() {
                if height <= next_height {
                    return Some((moved_value.clone(), next_height));
                } else {
                    prev = Some(moved_value);
                    continue;
                }
            }
            if height > prev.unwrap().get_height() && height <= next_height {
                return Some((moved_value.clone(), moved_value.get_height()));
            } else {
                prev = Some(moved_value);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::rocksdb::moved_value_history::{InMemoryMovedValueHistory, MovedValueHistory};

    use super::ErgoMovedValue;

    #[tokio::test]
    async fn test_in_memory_single_insertion() {
        let mut history = InMemoryMovedValueHistory::new();
        let height = 1234;
        let mv = gen_moved_value(height);
        history.append(mv.clone()).await;

        // Test exact height
        assert_eq!(history.get(height).await, Some((mv.clone(), height)));

        // Test lesser height
        assert_eq!(history.get(height - 10).await, Some((mv.clone(), height)));

        // Test greater height
        assert_eq!(history.get(height + 10).await, None);
    }

    #[tokio::test]
    async fn test_in_memory_2_insertions() {
        let mut history = InMemoryMovedValueHistory::new();
        let height = 1234;
        let mv_0 = gen_moved_value(height);
        let mv_1 = gen_moved_value(height + 10);
        history.append(mv_0.clone()).await;
        history.append(mv_1.clone()).await;

        // Test exact height
        assert_eq!(history.get(height).await, Some((mv_0.clone(), height)));

        // Test lesser height
        assert_eq!(history.get(height - 10).await, Some((mv_0.clone(), height)));

        // Test greater height
        assert_eq!(history.get(height + 1).await, Some((mv_1.clone(), height + 10)));
    }

    fn gen_moved_value(height: u32) -> ErgoMovedValue {
        ErgoMovedValue::Applied(super::ErgoUserValue {
            imported_value: vec![],
            exported_value: vec![],
            progress_point: height,
        })
    }
}
