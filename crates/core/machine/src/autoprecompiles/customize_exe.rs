use sp1_core_executor::Program;
use powdr_autoprecompiles::{BasicBlock, blocks::collect_basic_blocks};
use crate::autoprecompiles::{CompiledProgram, adapter::Sp1ApcAdapter, program::Sp1Program, instruction_handler::Sp1InstructionHandler};
use std::collections::BTreeSet;

pub fn customize(
	original_program: Program,
	labels: &BTreeSet<u64>,
) -> CompiledProgram {
	let basic_blocks = collect_basic_blocks::<Sp1ApcAdapter>(
		&Sp1Program(original_program),
		labels,
		&Sp1InstructionHandler::new(),
	);

	CompiledProgram {
		basic_blocks,
	}
}