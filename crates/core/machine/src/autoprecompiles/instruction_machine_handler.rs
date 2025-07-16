use powdr_autoprecompiles::InstructionMachineHandler;
use powdr_number::BabyBearField;

#[derive(Clone)]
pub struct Sp1InstructionMachineHandler;

impl InstructionMachineHandler<BabyBearField> for Sp1InstructionMachineHandler {
    fn get_instruction_air(
        &self,
        instruction: &powdr_autoprecompiles::SymbolicInstructionStatement<BabyBearField>,
    ) -> Option<&powdr_autoprecompiles::SymbolicMachine<BabyBearField>> {
        todo!()
    }
}
