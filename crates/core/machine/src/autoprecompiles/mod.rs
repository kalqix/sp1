pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod memory_bus_interaction;
pub mod program;

use powdr_autoprecompiles::blocks::{collect_basic_blocks, BasicBlock};
use sp1_build::{BuildArgs, DEFAULT_TARGET_64};
use sp1_core_executor::Program;
use std::collections::BTreeSet;

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, instruction::Sp1Instruction,
    instruction_handler::Sp1InstructionHandler, program::Sp1Program,
};

pub fn build_elf_path(guest_path: &str, build_args: BuildArgs) -> String {
    let guest_path = std::path::Path::new(guest_path).to_path_buf();
    // Currently we only take the first elf path built from the given `guest_path`, assuming that
    // there's only one binary in `guest_path` TODO: add a filter input argument and assert only
    // one elf is left after filtering
    let elf_path =
        sp1_build::execute_build_program(&build_args, Some(guest_path)).unwrap()[0].1.clone();
    elf_path.to_string()
}

pub fn compile_exe_with_elf(elf: &[u8]) -> CompiledProgram {
    let labels = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf);

    let original_program = Program::from(elf).unwrap();

    CompiledProgram::new(original_program, &labels.jumpdests)
}

pub fn compile_exe(guest_path: &str) -> CompiledProgram {
    let build_args = powdr_default_build_args();
    let elf_path = build_elf_path(guest_path, build_args);
    let elf = std::fs::read(elf_path).unwrap();

    compile_exe_with_elf(&elf)
}

pub fn powdr_default_build_args() -> BuildArgs {
    BuildArgs { build_target: DEFAULT_TARGET_64.to_string(), ..Default::default() }
}

pub struct CompiledProgram {
    pub basic_blocks: Vec<BasicBlock<Sp1Instruction>>,
}

impl CompiledProgram {
    pub fn new(original_program: Program, labels: &BTreeSet<u64>) -> Self {
        let basic_blocks = collect_basic_blocks::<Sp1ApcAdapter>(
            &Sp1Program::from(original_program),
            labels,
            &Sp1InstructionHandler::new(),
        );

        Self { basic_blocks }
    }
}

#[cfg(test)]
mod machine_extraction_tests {
    use std::{fs, io, path::Path};

    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use slop_baby_bear::BabyBear;

    use crate::{
        autoprecompiles::{bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler},
        utils::setup_logger,
    };

    #[test]
    fn test_extract_machine() {
        setup_logger();
        let instruction_handler = Sp1InstructionHandler::<BabyBear>::new();
        let airs = instruction_handler.airs();
        let rendered = airs
            .map(|(instruction_type, air)| {
                format!("# {instruction_type:?}\n{}", air.render(&sp1_bus_map()))
            })
            .join("\n\n\n");

        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("extracted_constraints.txt");
        match fs::read_to_string(&path) {
            // Snapshot exists, compare it with the extracted constraints
            Ok(expected) => {
                assert_eq!(rendered, expected)
            }

            // Snapshot does not exist, create it
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(&path, &rendered).unwrap();
                panic!("Created new snapshot at {path:?}. Inspect it, then rerun the tests.");
            }

            Err(_) => panic!(),
        }
    }
}

#[cfg(test)]
mod apc_snapshot_tests {
    use super::*;
    use powdr_autoprecompiles::{build, BasicBlock, DegreeBound, InstructionHandler, VmConfig};
    use pretty_assertions::assert_eq;
    use sp1_core_executor::{Instruction, Opcode};
    use std::{fs, path::Path};

    use crate::{
        autoprecompiles::{
            adapter::Sp1ApcAdapter, bus_interaction_handler::Sp1BusInteractionHandler,
            bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler,
        },
        utils::setup_logger,
    };
    const GUEST_FIBONACCI: &str = "../../test-artifacts/programs/fibonacci";

    fn assert_machine_output(basic_block: Vec<Instruction>, test_name: &str) {
        let vm_config = VmConfig {
            instruction_handler: &Sp1InstructionHandler::new(),
            bus_interaction_handler: Sp1BusInteractionHandler::default(),
            bus_map: sp1_bus_map(),
        };
        // TODO: Is this correct?
        let degree_bound = DegreeBound { identities: 3, bus_interactions: 2 };
        let block = BasicBlock {
            start_pc: 0,
            statements: basic_block.into_iter().map(Into::into).collect(),
        };

        let original_air = vm_config
            .instruction_handler
            .get_instruction_air(&block.statements[0])
            .expect("Failed to get instruction AIR")
            .render(&vm_config.bus_map);
        tracing::info!("Original AIR:\n{original_air}");

        let apc = build::<Sp1ApcAdapter>(block, vm_config, degree_bound, 1234, None).unwrap();
        let actual = apc.machine.render(&sp1_bus_map());

        let expected_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("apc_snapshots")
            .join(format!("{test_name}.txt"));

        match fs::read_to_string(&expected_path) {
            Ok(expected) => {
                assert_eq!(
                    expected.trim(),
                    actual.trim(),
                    "The output of `{test_name}` does not match the expected output. \
                 To re-generate the expected output, delete the file `{}` and re-run the test.",
                    expected_path.display()
                );
            }
            _ => {
                // Write the new expected output to the file
                fs::create_dir_all(expected_path.parent().unwrap()).unwrap();
                fs::write(&expected_path, actual).unwrap();

                tracing::info!(
                    "Expected output for `{test_name}` was updated. Re-run the test to confirm."
                );
            }
        }
    }

    #[test]
    fn test_add() {
        setup_logger();
        let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 0, 5, false, true)];
        assert_machine_output(basic_block, "addi")
    }

    #[test]
    fn test_collect_basic_blocks() {
        setup_logger();

        let build_args = powdr_default_build_args();
        let elf_path = build_elf_path(GUEST_FIBONACCI, build_args);
        let elf = std::fs::read(elf_path).unwrap();

        let jumpdest_set = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(&elf).jumpdests;
        let original_program = Program::from(&elf).unwrap();
        let compiled_program = CompiledProgram::new(original_program, &jumpdest_set);

        // Check total number of basic blocks produced
        let basic_blocks = compiled_program.basic_blocks;
        let basic_blocks_length = basic_blocks.len();
        assert_eq!(basic_blocks_length, 1601);

        // Check the validity of each basic block
        let instruction_handler = Sp1InstructionHandler::<slop_baby_bear::BabyBear>::new();

        basic_blocks.iter().enumerate().fold(None::<Sp1Instruction>, |prior, (idx, bb)| {
            // Every block must be non-empty
            assert!(!bb.statements.is_empty(), "Basic block must not be empty");

            // A basic block must:
            // start with a not allowed instruction (in which case it's alone in its own block)
            // OR start with a target instruction
            // OR the last instruction of the prior block is branching/not allowed instruction
            // OR is the first block
            let first = &bb.statements[0];
            if !instruction_handler.is_allowed(first) {
                assert!(
                    bb.statements.len() == 1,
                    "Block with not allowed instruction must be in its own block"
                );
            } else if idx != 0 {
                let prev = prior.as_ref().expect("Prior should be set after the first iteration");
                assert!(
                    instruction_handler.is_branching(prev)
                        || jumpdest_set.contains(&bb.start_pc)
                        || !instruction_handler.is_allowed(prev),
                    "Block must start at a jumpdest or after a branching instruction"
                );
            }

            // Update the last instruction of the prior block for the next iteration
            Some(bb.statements.last().unwrap().clone())
        });
    }
}
