use crate::{
    vm::shapes::{EventCosts, EventCounts},
    RiscvAirId,
};

/// The number of rows in the `ByteChip`.
pub const BYTE_NUM_ROWS: u64 = 1 << 16;

/// The number of rows in the `RangeChip`.
pub const RANGE_NUM_ROWS: u64 = 1 << 17;
