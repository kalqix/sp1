use crate::autoprecompiles::instruction::Sp1Instruction;
use powdr_autoprecompiles::blocks::Program;

pub struct Sp1Program(sp1_core_executor::Program);

impl Program<Sp1Instruction> for Sp1Program {
    fn base_pc(&self) -> u32 {
        // TODO: change the return type to u64 and avoid the cast
        self.0.pc_base.try_into().unwrap()
    }

    fn pc_step(&self) -> u32 {
        // See [Program::fetch]
        4
    }

    fn instructions(&self) -> Box<dyn Iterator<Item = Sp1Instruction> + '_> {
        Box::new(self.0.instructions.iter().map(|inst| Sp1Instruction(*inst)))
    }
}
