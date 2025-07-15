use powdr_autoprecompiles::blocks::Instruction;
use serde::{Deserialize, Serialize};
use slop_algebra::AbstractField;
use slop_baby_bear::BabyBear;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sp1Instruction(pub sp1_core_executor::Instruction);

impl Instruction<BabyBear> for Sp1Instruction {
    fn opcode(&self) -> usize {
        unimplemented!()
    }

    fn into_symbolic_instruction(
        self,
    ) -> powdr_autoprecompiles::SymbolicInstructionStatement<BabyBear> {
        powdr_autoprecompiles::SymbolicInstructionStatement {
            opcode: (self.0.opcode as u8) as usize,
            args: vec![
                BabyBear::from_canonical_u32(self.0.op_a as u32),
                BabyBear::from_canonical_u32(self.0.op_b as u32),
                BabyBear::from_canonical_u32(self.0.op_c as u32),
                BabyBear::from_canonical_u32(self.0.imm_b as u32),
                BabyBear::from_canonical_u32(self.0.imm_c as u32),
            ],
        }
    }
}
