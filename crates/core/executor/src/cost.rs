use crate::{
    vm::shapes::{EventCosts, EventCounts},
    RiscvAirId,
};

/// The number of rows in the `ByteChip`.
pub const BYTE_NUM_ROWS: u64 = 1 << 16;

/// The number of rows in the `RangeChip`.
pub const RANGE_NUM_ROWS: u64 = 1 << 17;

// When counting events, we currently assume that all APCs succeed. This might not be the case,
// because we can't currently handle state or memory bump events.
// Assuming 1% of APC calls fail, and the APC has an effectiveness of 11x, that means that we can
// expect the actual number of trace cells to be 10% higher than they would be if no APC calls were
// cancelled.
const APC_PENALTY: f64 = 1.10;

/// Estimates the LDE area.
#[must_use]
pub fn estimate_trace_elements(
    num_events_per_air: &EventCounts<RiscvAirId>,
    costs_per_air: &EventCosts,
    program_size: u64,
    internal_syscalls_air_id: &[RiscvAirId],
) -> (u64, u64) {
    // Compute APC costs
    let (mut cells, mut max_height) = num_events_per_air.apc.iter().fold(
        (0u64, 0u64),
        |(cells, max_height), (apc_id, num_events)| {
            let width = costs_per_air.apc[apc_id];
            #[allow(clippy::cast_precision_loss)]
            let penalized_trace_cells =
                ((num_events.next_multiple_of(32) * width) as f64 * APC_PENALTY).ceil() as u64;
            let new_cells = cells + penalized_trace_cells;
            let new_max_height = max_height.max(*num_events);
            (new_cells, new_max_height)
        },
    );

    let costs_per_air = costs_per_air.core;
    let num_events_per_air = num_events_per_air.core;

    // Compute the byte chip contribution.
    cells += BYTE_NUM_ROWS * costs_per_air[RiscvAirId::Byte];

    // Compute the range chip contribution.
    cells += RANGE_NUM_ROWS * costs_per_air[RiscvAirId::Range];

    // Compute the program chip contribution.
    cells += program_size * costs_per_air[RiscvAirId::Program];

    // Compute the bump contribution.
    cells += (num_events_per_air[RiscvAirId::MemoryBump].next_multiple_of(32))
        * costs_per_air[RiscvAirId::MemoryBump];
    max_height = max_height.max(num_events_per_air[RiscvAirId::MemoryBump]);
    cells += (num_events_per_air[RiscvAirId::StateBump].next_multiple_of(32))
        * costs_per_air[RiscvAirId::StateBump];
    max_height = max_height.max(num_events_per_air[RiscvAirId::StateBump]);

    // Compute the add chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Add]).next_multiple_of(32) * costs_per_air[RiscvAirId::Add];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Add]);

    // Compute the addi chip contribution.
    cells += (num_events_per_air[RiscvAirId::Addi]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Addi];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Addi]);

    // Compute that addw chip contribution.
    cells += (num_events_per_air[RiscvAirId::Addw]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Addw];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Addw]);

    // Compute the sub chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Sub]).next_multiple_of(32) * costs_per_air[RiscvAirId::Sub];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Sub]);

    // Compute that subw chip contribution.
    cells += (num_events_per_air[RiscvAirId::Subw]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Subw];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Subw]);

    // Compute the bitwise chip contribution.
    cells += (num_events_per_air[RiscvAirId::Bitwise]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Bitwise];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Bitwise]);
    // Compute the divrem chip contribution.
    cells += (num_events_per_air[RiscvAirId::DivRem]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::DivRem];
    max_height = max_height.max(num_events_per_air[RiscvAirId::DivRem]);
    // Compute the lt chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Lt]).next_multiple_of(32) * costs_per_air[RiscvAirId::Lt];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Lt]);
    // Compute the mul chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Mul]).next_multiple_of(32) * costs_per_air[RiscvAirId::Mul];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Mul]);
    // Compute the shift left chip contribution.
    cells += (num_events_per_air[RiscvAirId::ShiftLeft]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::ShiftLeft];
    max_height = max_height.max(num_events_per_air[RiscvAirId::ShiftLeft]);
    // Compute the shift right chip contribution.
    cells += (num_events_per_air[RiscvAirId::ShiftRight]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::ShiftRight];
    max_height = max_height.max(num_events_per_air[RiscvAirId::ShiftRight]);
    // Compute the memory local chip contribution.
    cells += (num_events_per_air[RiscvAirId::MemoryLocal]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::MemoryLocal];
    max_height = max_height.max(num_events_per_air[RiscvAirId::MemoryLocal]);
    // Compute the page prot local chip contribution.
    cells += (num_events_per_air[RiscvAirId::PageProtLocal]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::PageProtLocal];
    max_height = max_height.max(num_events_per_air[RiscvAirId::PageProtLocal]);
    // Compute the branch chip contribution.
    cells += (num_events_per_air[RiscvAirId::Branch]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Branch];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Branch]);
    // Compute the jal chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Jal]).next_multiple_of(32) * costs_per_air[RiscvAirId::Jal];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Jal]);
    // Compute the jalr chip contribution.
    cells += (num_events_per_air[RiscvAirId::Jalr]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Jalr];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Jalr]);
    // Compute the utype chip contribution.
    cells += (num_events_per_air[RiscvAirId::UType]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::UType];
    max_height = max_height.max(num_events_per_air[RiscvAirId::UType]);
    // Compute the memory instruction chip contribution.
    cells += (num_events_per_air[RiscvAirId::LoadByte]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::LoadByte];
    max_height = max_height.max(num_events_per_air[RiscvAirId::LoadByte]);
    cells += (num_events_per_air[RiscvAirId::LoadHalf]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::LoadHalf];
    max_height = max_height.max(num_events_per_air[RiscvAirId::LoadHalf]);
    cells += (num_events_per_air[RiscvAirId::LoadWord]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::LoadWord];
    max_height = max_height.max(num_events_per_air[RiscvAirId::LoadWord]);
    cells += (num_events_per_air[RiscvAirId::LoadDouble]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::LoadDouble];
    max_height = max_height.max(num_events_per_air[RiscvAirId::LoadDouble]);
    cells += (num_events_per_air[RiscvAirId::LoadX0]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::LoadX0];
    max_height = max_height.max(num_events_per_air[RiscvAirId::LoadX0]);
    cells += (num_events_per_air[RiscvAirId::StoreByte]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::StoreByte];
    max_height = max_height.max(num_events_per_air[RiscvAirId::StoreByte]);
    cells += (num_events_per_air[RiscvAirId::StoreHalf]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::StoreHalf];
    max_height = max_height.max(num_events_per_air[RiscvAirId::StoreHalf]);
    cells += (num_events_per_air[RiscvAirId::StoreWord]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::StoreWord];
    max_height = max_height.max(num_events_per_air[RiscvAirId::StoreWord]);
    cells += (num_events_per_air[RiscvAirId::StoreDouble]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::StoreWord]; // TODO: is this a bug from sp1 original?
    max_height = max_height.max(num_events_per_air[RiscvAirId::StoreDouble]);
    // Compute the page protection chip contribution.
    cells += (num_events_per_air[RiscvAirId::PageProt]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::PageProt];
    max_height = max_height.max(num_events_per_air[RiscvAirId::PageProt]);

    // Compute the instruction fetch chip contribution.
    cells += (num_events_per_air[RiscvAirId::InstructionFetch]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::InstructionFetch];
    max_height = max_height.max(num_events_per_air[RiscvAirId::InstructionFetch]);
    // Compute the instruction decode chip contribution.
    cells += (num_events_per_air[RiscvAirId::InstructionDecode]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::InstructionDecode];
    max_height = max_height.max(num_events_per_air[RiscvAirId::InstructionDecode]);

    // Compute the syscall instruction chip contribution.
    cells += (num_events_per_air[RiscvAirId::SyscallInstrs]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::SyscallInstrs];
    max_height = max_height.max(num_events_per_air[RiscvAirId::SyscallInstrs]);

    // Compute the syscall core chip contribution.
    cells += (num_events_per_air[RiscvAirId::SyscallCore]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::SyscallCore];
    max_height = max_height.max(num_events_per_air[RiscvAirId::SyscallCore]);

    // Compute the global chip contribution.
    cells += (num_events_per_air[RiscvAirId::Global]).next_multiple_of(32)
        * costs_per_air[RiscvAirId::Global];
    max_height = max_height.max(num_events_per_air[RiscvAirId::Global]);

    for &syscall_air_id in internal_syscalls_air_id {
        let rows_per_event = syscall_air_id.rows_per_event() as u64;
        let num_rows = (num_events_per_air[syscall_air_id] * rows_per_event).next_multiple_of(32);
        cells += num_rows * costs_per_air[syscall_air_id];
        max_height = max_height.max(num_rows);
        // Currently, all precompiles with `rows_per_event > 1` have the respective control chip.
        if rows_per_event > 1 {
            cells += num_events_per_air[syscall_air_id].next_multiple_of(32)
                * costs_per_air[syscall_air_id.control_air_id().unwrap()];
        }
    }

    (cells, max_height)
}

/// Pads the event counts to account for the worst case jump in events across N cycles.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn pad_rv64im_event_counts(
    mut event_counts: EventCounts<RiscvAirId>,
    num_cycles: u64,
) -> EventCounts<RiscvAirId> {
    event_counts.core.iter_mut().for_each(|(k, v)| match k {
        RiscvAirId::PageProtLocal => *v += 16 * num_cycles,
        RiscvAirId::MemoryLocal => *v += 128 * num_cycles,
        RiscvAirId::Global => *v += 512 * num_cycles,
        _ => *v += num_cycles,
    });
    // TODO: padding increases ALL apc and non-apc events by `num_cycles`, which defaults to 16.
    // This can preemptively segment if the sum of all APC sizes is very large.
    // To be more exact, if the sum of all APC columns is larger than 1/16 of the cell limit per
    // shard of 1<<29 - 1<<27, or 25 million columns, segmentation will happen every 16
    // instructions.
    event_counts.apc.iter_mut().for_each(|(_, v)| *v += num_cycles);
    event_counts
}
