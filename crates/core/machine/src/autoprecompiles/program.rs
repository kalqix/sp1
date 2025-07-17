use crate::autoprecompiles::instruction::Sp1Instruction;
use powdr_autoprecompiles::blocks::Program;

pub struct Sp1Program(pub sp1_core_executor::Program);

impl Program<Sp1Instruction> for Sp1Program {
    fn base_pc(&self) -> u64 {
        self.0.pc_base
    }

    fn pc_step(&self) -> u32 {
        // See [Program::fetch]
        4
    }

    fn instructions(&self) -> Box<dyn Iterator<Item = Sp1Instruction> + '_> {
        Box::new(self.0.instructions.iter().map(|inst| Sp1Instruction(*inst)))
    }
}
