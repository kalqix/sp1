use crate::cpu::columns::InstructionCols;
use powdr_autoprecompiles::blocks::Instruction;
use serde::{Deserialize, Serialize};
use slop_algebra::PrimeField32;
use slop_baby_bear::BabyBear;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sp1Instruction(pub sp1_core_executor::Instruction);

impl From<sp1_core_executor::Instruction> for Sp1Instruction {
    fn from(instr: sp1_core_executor::Instruction) -> Self {
        Self(instr)
    }
}

impl Instruction<BabyBear> for Sp1Instruction {
    fn opcode(&self) -> usize {
        self.0.opcode as usize
    }

    fn into_symbolic_instruction(
        self,
    ) -> powdr_autoprecompiles::SymbolicInstructionStatement<BabyBear> {
        // TODO: This is wrong.
        // Should be: (pc (3 elements!), instruction (13 elements), instruction_field_consts (3 elements))
        // See: crates/core/machine/src/air/program.rs
        // TODO: Also, powdr_autoprecompiles makes wrong assumptions about the
        // structure of the PC lookup (e.g. assuming 1 element for the PC), see:
        // autoprecompiles/src/lib.rs
        let mut instruction_cols = InstructionCols::<BabyBear>::default();
        instruction_cols.populate(&self.0);
        let mut columns = instruction_cols.into_iter();
        powdr_autoprecompiles::SymbolicInstructionStatement {
            opcode: columns.next().unwrap().as_canonical_u32() as usize,
            args: columns.collect(),
        }
    }
}
