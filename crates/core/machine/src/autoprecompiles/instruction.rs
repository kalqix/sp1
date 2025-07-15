use powdr_autoprecompiles::blocks::Instruction;
use serde::{Deserialize, Serialize};
use slop_baby_bear::BabyBear;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sp1Instruction(sp1_core_executor::Instruction);

impl Instruction<BabyBear> for Sp1Instruction {
    fn opcode(&self) -> usize {
        todo!()
    }

    fn into_symbolic_instruction(
        self,
    ) -> powdr_autoprecompiles::SymbolicInstructionStatement<BabyBear> {
        todo!()
    }
}
