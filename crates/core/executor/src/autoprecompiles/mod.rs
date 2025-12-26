use std::sync::Arc;

use hashbrown::HashMap;
use powdr_autoprecompiles::execution::{ApcCandidates, Snapshot};

use crate::{
    events::ByteLookupEvent, Apc, ExecutionRecord, ExecutionReport, ExecutionState, LocalCounts,
};

pub type Sp1ApcCandidates = ApcCandidates<ExecutionState, Apc, Sp1Snapshot>;

#[derive(Clone, Debug)]
pub struct Sp1Snapshot(pub Arc<ExecutionSnapshot>);

impl Snapshot for Sp1Snapshot {
    fn instret(&self) -> usize {
        self.0.record.cpu_event_count as usize
    }
}

#[derive(Debug)]
pub struct ExecutionSnapshot {
    pub record: ExecutionRecordSnapshot,
    pub local_counts: LocalCounts,
    pub report: ExecutionReport,
    pub pc: u64,
}

#[derive(Debug)]
pub struct ExecutionRecordSnapshot {
    pub cpu_event_count: u32,
    pub add_events_len: usize,
    pub addw_events_len: usize,
    pub addi_events_len: usize,
    pub mul_events_len: usize,
    pub sub_events_len: usize,
    pub subw_events_len: usize,
    pub bitwise_events_len: usize,
    pub shift_left_events_len: usize,
    pub shift_right_events_len: usize,
    pub divrem_events_len: usize,
    pub lt_events_len: usize,
    pub memory_load_byte_events_len: usize,
    pub memory_load_half_events_len: usize,
    pub memory_load_word_events_len: usize,
    pub memory_load_x0_events_len: usize,
    pub memory_load_double_events_len: usize,
    pub memory_store_byte_events_len: usize,
    pub memory_store_half_events_len: usize,
    pub memory_store_word_events_len: usize,
    pub memory_store_double_events_len: usize,
    pub utype_events_len: usize,
    pub branch_events_len: usize,
    pub jal_events_len: usize,
    pub jalr_events_len: usize,
    pub instruction_fetch_events_len: usize,
    pub instruction_decode_events_len: usize,
    pub global_page_prot_initialize_events_len: usize,
    pub global_page_prot_finalize_events_len: usize,
    pub cpu_local_page_prot_access_len: usize,
    pub byte_lookups: HashMap<ByteLookupEvent, isize>,
    pub precompile_events_len: usize,
    pub global_memory_initialize_events_len: usize,
    pub global_memory_finalize_events_len: usize,
    pub cpu_local_memory_access_len: usize,
    pub syscall_events_len: usize,
    pub apc_events_len: usize,
    pub global_interaction_event_count: u32,
    pub bump_memory_events_len: usize,
    pub bump_state_events_len: usize,
}

impl From<&ExecutionRecord> for ExecutionRecordSnapshot {
    fn from(record: &ExecutionRecord) -> Self {
        ExecutionRecordSnapshot {
            cpu_event_count: record.cpu_event_count,
            add_events_len: record.add_events.len(),
            addw_events_len: record.addw_events.len(),
            addi_events_len: record.addi_events.len(),
            mul_events_len: record.mul_events.len(),
            sub_events_len: record.sub_events.len(),
            subw_events_len: record.subw_events.len(),
            bitwise_events_len: record.bitwise_events.len(),
            shift_left_events_len: record.shift_left_events.len(),
            shift_right_events_len: record.shift_right_events.len(),
            divrem_events_len: record.divrem_events.len(),
            lt_events_len: record.lt_events.len(),
            memory_load_byte_events_len: record.memory_load_byte_events.len(),
            memory_load_half_events_len: record.memory_load_half_events.len(),
            memory_load_word_events_len: record.memory_load_word_events.len(),
            memory_load_x0_events_len: record.memory_load_x0_events.len(),
            memory_load_double_events_len: record.memory_load_double_events.len(),
            memory_store_byte_events_len: record.memory_store_byte_events.len(),
            memory_store_half_events_len: record.memory_store_half_events.len(),
            memory_store_word_events_len: record.memory_store_word_events.len(),
            memory_store_double_events_len: record.memory_store_double_events.len(),
            utype_events_len: record.utype_events.len(),
            branch_events_len: record.branch_events.len(),
            jal_events_len: record.jal_events.len(),
            jalr_events_len: record.jalr_events.len(),
            byte_lookups: record.byte_lookups.clone(),
            precompile_events_len: record.precompile_events.len(),
            global_memory_initialize_events_len: record.global_memory_initialize_events.len(),
            global_memory_finalize_events_len: record.global_memory_finalize_events.len(),
            cpu_local_memory_access_len: record.cpu_local_memory_access.len(),
            syscall_events_len: record.syscall_events.len(),
            apc_events_len: record.apc_events.len(),
            global_interaction_event_count: record.global_interaction_event_count,
            bump_memory_events_len: record.bump_memory_events.len(),
            bump_state_events_len: record.bump_state_events.len(),
            instruction_fetch_events_len: record.instruction_fetch_events.len(),
            instruction_decode_events_len: record.instruction_decode_events.len(),
            global_page_prot_initialize_events_len: record.global_page_prot_initialize_events.len(),
            global_page_prot_finalize_events_len: record.global_page_prot_finalize_events.len(),
            cpu_local_page_prot_access_len: record.cpu_local_page_prot_access.len(),
        }
    }
}
