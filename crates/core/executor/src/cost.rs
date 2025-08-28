use crate::{EventCosts, EventCounts, RiscvAirId};

const BYTE_NUM_ROWS: u64 = 1 << 16;
const RANGE_NUM_ROWS: u64 = 1 << 17;

/// Estimates the LDE area.
#[must_use]
pub fn estimate_trace_elements(
    num_events_per_air: &EventCounts<RiscvAirId>,
    costs_per_air: &EventCosts,
    program_size: u64,
    internal_syscalls_air_id: &[RiscvAirId],
) -> (u64, u64) {
    let mut max_height = 0;

    // Compute APC costs
    let mut cells = 0;
    for (apc_id, num_events) in num_events_per_air.apc.iter().enumerate() {
        tracing::info!("apc id: {:?}", apc_id);
        tracing::info!("apc costs: {:?}", costs_per_air.apc);
        let width = costs_per_air.apc[apc_id];
        tracing::info!(
            "apc_id: {}, num_events: {}, width: {}, apc_cells: {}",
            apc_id,
            num_events,
            width,
            num_events * width
        );
        cells += num_events * width;
        max_height = max_height.max(*num_events);
    }

    // Compute the byte chip contribution.
    cells += BYTE_NUM_ROWS * costs_per_air.core[RiscvAirId::Byte];

    // Compute the range chip contribution.
    cells += RANGE_NUM_ROWS * costs_per_air.core[RiscvAirId::Range];

    // Compute the program chip contribution.
    cells += program_size * costs_per_air.core[RiscvAirId::Program];

    // Compute the bump contribution.
    cells += (num_events_per_air.core[RiscvAirId::MemoryBump].next_multiple_of(32))
        * costs_per_air.core[RiscvAirId::MemoryBump];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::MemoryBump]);
    cells += (num_events_per_air.core[RiscvAirId::StateBump].next_multiple_of(32))
        * costs_per_air.core[RiscvAirId::StateBump];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::StateBump]);

    // Compute the add chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Add]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Add];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Add]);

    // Compute the addi chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Addi]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Addi];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Addi]);

    // Compute that addw chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Addw]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Addw];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Addw]);

    // Compute the sub chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Sub]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Sub];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Sub]);

    // Compute that subw chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Subw]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Subw];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Subw]);

    // Compute the bitwise chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Bitwise]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Bitwise];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Bitwise]);
    // Compute the divrem chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::DivRem]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::DivRem];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::DivRem]);
    // Compute the lt chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Lt]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Lt];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Lt]);
    // Compute the mul chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Mul]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Mul];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Mul]);
    // Compute the shift left chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::ShiftLeft]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::ShiftLeft];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::ShiftLeft]);
    // Compute the shift right chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::ShiftRight]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::ShiftRight];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::ShiftRight]);
    // Compute the memory local chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::MemoryLocal]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::MemoryLocal];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::MemoryLocal]);
    // Compute the branch chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Branch]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Branch];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Branch]);
    // Compute the jal chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Jal]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Jal];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Jal]);
    // Compute the jalr chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Jalr]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Jalr];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Jalr]);
    // Compute the utype chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::UType]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::UType];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::UType]);
    // Compute the memory instruction chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::LoadByte]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::LoadByte];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::LoadByte]);
    cells += (num_events_per_air.core[RiscvAirId::LoadHalf]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::LoadHalf];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::LoadHalf]);
    cells += (num_events_per_air.core[RiscvAirId::LoadWord]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::LoadWord];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::LoadWord]);
    cells += (num_events_per_air.core[RiscvAirId::LoadDouble]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::LoadDouble];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::LoadDouble]);
    cells += (num_events_per_air.core[RiscvAirId::LoadX0]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::LoadX0];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::LoadX0]);
    cells += (num_events_per_air.core[RiscvAirId::StoreByte]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::StoreByte];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::StoreByte]);
    cells += (num_events_per_air.core[RiscvAirId::StoreHalf]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::StoreHalf];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::StoreHalf]);
    cells += (num_events_per_air.core[RiscvAirId::StoreWord]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::StoreWord];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::StoreWord]);
    cells += (num_events_per_air.core[RiscvAirId::StoreDouble]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::StoreWord]; // TODO: is this a bug from sp1 original?
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::StoreDouble]);

    // Compute the syscall instruction chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::SyscallInstrs]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::SyscallInstrs];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::SyscallInstrs]);

    // Compute the syscall core chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::SyscallCore]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::SyscallCore];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::SyscallCore]);

    // Compute the global chip contribution.
    cells += (num_events_per_air.core[RiscvAirId::Global]).next_multiple_of(32)
        * costs_per_air.core[RiscvAirId::Global];
    max_height = max_height.max(num_events_per_air.core[RiscvAirId::Global]);

    for &syscall_air_id in internal_syscalls_air_id {
        let rows_per_event = syscall_air_id.rows_per_event() as u64;
        let num_rows =
            (num_events_per_air.core[syscall_air_id] * rows_per_event).next_multiple_of(32);
        cells += num_rows * costs_per_air.core[syscall_air_id];
        max_height = max_height.max(num_rows);
        // Currently, all precompiles with `rows_per_event > 1` have the respective control chip.
        if rows_per_event > 1 {
            cells += num_events_per_air.core[syscall_air_id].next_multiple_of(32)
                * costs_per_air.core[syscall_air_id.control_air_id().unwrap()];
        }
    }

    (cells, max_height)
}

/// Pads the event counts to account for the worst case jump in events across N cycles.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn pad_rv32im_event_counts(
    mut event_counts: EventCounts<RiscvAirId>,
    num_cycles: u64,
) -> EventCounts<RiscvAirId> {
    event_counts.core.iter_mut().for_each(|(k, v)| match k {
        RiscvAirId::MemoryLocal => *v += 64 * num_cycles,
        RiscvAirId::Global => *v += 512 * num_cycles,
        _ => *v += num_cycles,
    });
    // TODO: doing this for a large APC might preemtively stop a shard (if APC size is larger than
    // 1/16 of the cell limit per shard of 1<<29 - 1<<27)
    event_counts.apc.iter_mut().for_each(|v| *v += num_cycles);
    event_counts
}
