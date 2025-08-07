use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, instruction_handler::Sp1InstructionHandler, sp1_vm_config,
    DEFAULT_DEGREE_BOUND,
};
use powdr_autoprecompiles::{adapter::AdapterApc, blocks::BasicBlock, build};
use slop_baby_bear::BabyBear;
use sp1_core_executor::Instruction;

pub fn create_apc_from_instructions(
    original_instruction: &[Instruction],
) -> AdapterApc<Sp1ApcAdapter> {
    // Create a dummy basic block with the original instructions
    let block = BasicBlock {
        start_pc: 0,
        statements: original_instruction.iter().cloned().map(Into::into).collect(),
    };

    // Build the APC from the block
    build::<Sp1ApcAdapter>(
        block,
        sp1_vm_config(&Sp1InstructionHandler::<BabyBear>::new()),
        DEFAULT_DEGREE_BOUND,
        None,
    )
    .expect("Failed to build APC")
}
