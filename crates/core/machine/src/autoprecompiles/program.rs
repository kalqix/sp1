use crate::autoprecompiles::instruction::Sp1Instruction;
use powdr_autoprecompiles::blocks::Program;

pub struct Sp1Program(sp1_core_executor::Program);

impl Program<Sp1Instruction> for Sp1Program {
    fn base_pc(&self) -> u64 {
        self.0.pc_base
    }

    fn pc_step(&self) -> u32 {
        // See [Program::fetch]
        4
    }

    fn instructions(&self) -> Box<dyn Iterator<Item = Sp1Instruction> + '_> {
        Box::new(self.0.instructions.clone().into_iter().map(|inst| Sp1Instruction(inst)))
    }

    fn length(&self) -> u32 {
        self.0.instructions.len() as u32
    }
}

impl From<sp1_core_executor::Program> for Sp1Program {
    fn from(inner: sp1_core_executor::Program) -> Self {
        Sp1Program(inner)
    }
}
