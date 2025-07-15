use crate::autoprecompiles::instruction::Sp1Instruction;
use powdr_autoprecompiles::blocks::Program;

pub struct Sp1Program(sp1_core_executor::Program);

impl Program<Sp1Instruction> for Sp1Program {
    fn base_pc(&self) -> u32 {
        todo!()
    }

    fn pc_step(&self) -> u32 {
        todo!()
    }

    fn instructions(&self) -> Box<dyn Iterator<Item = Sp1Instruction> + '_> {
        todo!()
    }
}
