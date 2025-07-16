use crate::autoprecompiles::{
    bus_interaction_handler::Sp1BusInteractionHandler, candidate::Sp1Candidate,
    instruction::Sp1Instruction, instruction_machine_handler::InstructionAirs, program::Sp1Program,
};
use powdr_autoprecompiles::adapter::Adapter;
use powdr_number::{FieldElement, LargeInt};
use slop_algebra::{AbstractField, PrimeField32};
use slop_baby_bear::BabyBear;

struct Sp1ApcAdapter;

impl Adapter for Sp1ApcAdapter {
    type Field = BabyBear;

    type PowdrField = powdr_number::BabyBearField;

    type InstructionMachineHandler = InstructionAirs<powdr_number::BabyBearField>;

    type BusInteractionHandler = Sp1BusInteractionHandler;

    type Candidate = Sp1Candidate<Self>;

    type Program = Sp1Program;

    type Instruction = Sp1Instruction;

    fn into_field(e: Self::PowdrField) -> Self::Field {
        BabyBear::from_canonical_u32(e.to_integer().try_into_u32().unwrap())
    }

    fn from_field(e: Self::Field) -> Self::PowdrField {
        Self::PowdrField::from_bytes_le(&e.as_canonical_u32().to_le_bytes())
    }
}
