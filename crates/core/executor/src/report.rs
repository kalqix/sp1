use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::{Add, AddAssign},
};

use enum_map::{EnumArray, EnumMap};
use hashbrown::HashMap;

use crate::{
    events::{generate_execution_report, MemInstrEvent, PrecompileEvent, SyscallEvent},
    syscalls::SyscallCode,
    ITypeRecord, Opcode,
};

/// Counts the number of times an APC was invoked along with its success and failure reasons.
/// Note that in theory many reasons can lead to an APC failing, so the sum of the fields is *NOT*
/// necessarily equal to the total number of invocations.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ApcCount {
    /// The number of successful runs of this apc
    pub success: u64,
    /// The number of runs of this apc in which a state bump error occured
    pub state_bump_error: u64,
    /// The number of runs of this apc in which a memory bump error occured
    pub memory_bump_error: u64,
    /// The number of runs of this apc in which a segmentation occurred
    pub segmentation_error: u64,
}

/// An execution report.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The opcode counts.
    pub opcode_counts: Box<EnumMap<Opcode, u64>>,
    /// The syscall counts.
    pub syscall_counts: Box<EnumMap<SyscallCode, u64>>,
    /// The apc counts.
    pub apc_counts: Box<HashMap<u64, ApcCount>>,
    /// The cycle tracker counts.
    pub cycle_tracker: HashMap<String, u64>,
    /// Tracker for the number of `cycle-tracker-report-*` invocations for a specific label.
    pub invocation_tracker: HashMap<String, u64>,
    /// The unique memory address counts.
    pub touched_memory_addresses: u64,
    /// The gas, if it was calculated.
    pub gas: Option<u64>,
}

impl ExecutionReport {
    /// Compute the total number of instructions run during the execution.
    #[must_use]
    pub fn total_instruction_count(&self) -> u64 {
        self.opcode_counts.values().sum()
    }

    /// Compute the total number of syscalls made during the execution.
    #[must_use]
    pub fn total_syscall_count(&self) -> u64 {
        self.syscall_counts.values().sum()
    }

    /// The total size expected size (in bytes) of the execution report.
    #[must_use]
    pub fn total_record_size(&self) -> u64 {
        // todo!(n): make this precise.

        // Fix some average bound for each opcode.
        let avg_opcode_record_size = std::mem::size_of::<(MemInstrEvent, ITypeRecord)>();
        let total_opcode_records_size_bytes =
            self.opcode_counts.values().sum::<u64>() * avg_opcode_record_size as u64;

        // Take the maximum size of each precompile + 512 bytes for the vecs
        // todo: can we fix the array sizes in the precompile events?
        let syscall_avg_record_size = std::mem::size_of::<(SyscallEvent, PrecompileEvent)>() + 512;
        let total_syscall_records_size_bytes =
            self.syscall_counts.values().sum::<u64>() * syscall_avg_record_size as u64;

        total_opcode_records_size_bytes + total_syscall_records_size_bytes
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn counts_add_assign<K, V>(lhs: &mut EnumMap<K, V>, rhs: EnumMap<K, V>)
where
    K: EnumArray<V>,
    V: AddAssign,
{
    for (k, v) in rhs {
        lhs[k] += v;
    }
}

impl AddAssign for ExecutionReport {
    fn add_assign(&mut self, rhs: Self) {
        counts_add_assign(&mut self.opcode_counts, *rhs.opcode_counts);
        counts_add_assign(&mut self.syscall_counts, *rhs.syscall_counts);
        self.touched_memory_addresses += rhs.touched_memory_addresses;
    }
}

impl Add for ExecutionReport {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Display for ExecutionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(gas) = self.gas {
            writeln!(f, "gas: {gas}")?;
        }
        writeln!(f, "opcode counts ({} total instructions):", self.total_instruction_count())?;
        for line in generate_execution_report(self.opcode_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }

        writeln!(f, "syscall counts ({} total syscall instructions):", self.total_syscall_count())?;
        for line in generate_execution_report(self.syscall_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }

        Ok(())
    }
}
