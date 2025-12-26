use std::fmt::Display;

use crate::autoprecompiles::{
    bus_interaction_handler::Sp1BusInteractionHandler, bus_map::Sp1SpecificBuses,
    instruction::Sp1Instruction, instruction_handler::Sp1InstructionHandler, program::Sp1Program,
};
use powdr_autoprecompiles::{adapter::Adapter, blocks::BasicBlock, evaluation::EvaluationResult};
use powdr_number::{FieldElement, LargeInt};
use slop_algebra::{AbstractField, PrimeField32};
use sp1_autoprecompiles_common::Sp1MemoryBusInteraction;
use sp1_core_executor::ExecutionState;
use sp1_primitives::SP1Field;
use std::hash::Hash;
pub struct Sp1ApcAdapter;

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
    type AirId = usize;
    type ExecutionState = ExecutionState;

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
