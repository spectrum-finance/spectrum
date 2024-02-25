use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HandelMessage<C> {
    pub level: u32,
    pub individual_contribution: Option<C>,
    pub aggregate_contribution: C,
    /// If true, then receiver needs to contact sender
    pub contact_sender: bool,
}
