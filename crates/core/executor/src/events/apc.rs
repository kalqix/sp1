use serde::{Deserialize, Serialize};

use crate::ExecutionRecord;

#[derive(Deserialize, Serialize, Debug, Clone)]
/// Represents an apc event in the executor.
pub struct ApcEvent {
    /// The apc id
    pub id: u64,
    /// The record of the original instructions executed by the apc.
    pub record: ExecutionRecord,
}
