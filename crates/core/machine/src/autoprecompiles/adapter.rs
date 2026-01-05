use std::fmt::Display;

use crate::autoprecompiles::{
    bus_interaction_handler::Sp1BusInteractionHandler, bus_map::Sp1SpecificBuses,
    instruction::Sp1Instruction, instruction_handler::Sp1InstructionHandler,
    memory_bus_interaction::Sp1MemoryBusInteraction, program::Sp1Program,
};
use powdr_autoprecompiles::{adapter::Adapter, blocks::BasicBlock, evaluation::EvaluationResult};
use powdr_number::{FieldElement, LargeInt};
use slop_algebra::{AbstractField, PrimeField32};
use sp1_core_executor::ExecutionState as ExecutorExecutionState;
use sp1_primitives::SP1Field;
use std::hash::Hash;
pub struct Sp1ApcAdapter;

pub struct Sp1ExecutionState(pub ExecutorExecutionState);

impl Adapter for Sp1ApcAdapter {
    type Field = SP1Field;
    type PowdrField = powdr_number::KoalaBearField;
    type InstructionHandler = Sp1InstructionHandler<Self::Field>;
    type BusInteractionHandler = Sp1BusInteractionHandler;
    type Program = Sp1Program;
    type Instruction = Sp1Instruction;
    type MemoryBusInteraction<V: Ord + Clone + Eq + Display + Hash> = Sp1MemoryBusInteraction<V>;
    type CustomBusTypes = Sp1SpecificBuses;
    type ApcStats = EvaluationResult;
    type AirId = sp1_core_executor::RiscvAirId;
    type ExecutionState = Sp1ExecutionState;

    fn into_field(e: Self::PowdrField) -> Self::Field {
        Self::Field::from_canonical_u32(e.to_integer().try_into_u32().unwrap())
    }

    fn from_field(e: Self::Field) -> Self::PowdrField {
        Self::PowdrField::from_bytes_le(&e.as_canonical_u32().to_le_bytes())
    }

    fn should_skip_block(block: &BasicBlock<Self::Instruction>) -> bool {
        // Skip blocks with more than 1000 instructions
        block.statements.len() > 1000
    }
}

impl powdr_autoprecompiles::execution::ExecutionState for Sp1ExecutionState {
    type RegisterAddress = u8;
    type Value = u64;

    fn pc(&self) -> Self::Value {
        self.0.pc
    }

    fn reg(&self, address: &Self::RegisterAddress) -> Self::Value {
        let addr = *address as u64;
        self.0.memory.registers.get(addr).map(|entry| entry.value).unwrap_or(0)
    }
}
