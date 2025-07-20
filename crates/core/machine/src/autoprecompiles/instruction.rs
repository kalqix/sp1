use crate::cpu::columns::InstructionCols;
use powdr_autoprecompiles::blocks::Instruction;
use serde::{Deserialize, Serialize};
use slop_baby_bear::BabyBear;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sp1Instruction(pub sp1_core_executor::Instruction);

impl From<sp1_core_executor::Instruction> for Sp1Instruction {
    fn from(instr: sp1_core_executor::Instruction) -> Self {
        Self(instr)
    }
}

impl Instruction<BabyBear> for Sp1Instruction {
    fn pc_lookup_row(&self, _pc: Option<u64>) -> Vec<Option<BabyBear>> {
        // The PC lookup row has the following structure:
        // [pc_0, pc_1, pc_2, instruction_cols..., instruction_field_consts... (3 elements)]
        let mut instruction_cols = InstructionCols::<BabyBear>::default();
        instruction_cols.populate(&self.0);
        let instruction_cols = instruction_cols.into_iter().map(Some);
        // TODO: Provide the initial PC if available.
        [None, None, None].into_iter().chain(instruction_cols).chain([None, None, None]).collect()
    }
}
