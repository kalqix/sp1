use std::sync::Arc;

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, instruction::Sp1Instruction,
    instruction_handler::Sp1InstructionHandler, sp1_vm_config, DEFAULT_DEGREE_BOUND,
};
use powdr_autoprecompiles::{adapter::AdapterApc, blocks::BasicBlock, build};
use slop_baby_bear::BabyBear;
use sp1_core_executor::Program;

pub fn create_apcs(
    program: &Program,
    ranges: &[(usize, usize)],
) -> Vec<Arc<AdapterApc<Sp1ApcAdapter>>> {
    ranges
        .iter()
        .map(|(start, end)| {
            let instructions = program
                .instructions
                .get_proving_range(*start, *end)
                .iter()
                .cloned()
                .map(Sp1Instruction::from)
                .collect();
            // Create a dummy basic block with the original instructions
            let block = BasicBlock { start_pc: 0, statements: instructions };

            // Build the APC from the block
            build::<Sp1ApcAdapter>(
                block,
                sp1_vm_config(&Sp1InstructionHandler::<BabyBear>::new()),
                DEFAULT_DEGREE_BOUND,
                None,
            )
            .expect("Failed to build APC")
        })
        .map(Arc::new)
        .collect()
}
