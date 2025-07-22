pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod program;

use powdr_autoprecompiles::blocks::{collect_basic_blocks, BasicBlock};
use sp1_build::{generate_elf_paths, BuildArgs, DEFAULT_TARGET_64};
use sp1_core_executor::Program;
use std::collections::BTreeSet;

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, instruction::Sp1Instruction,
    instruction_handler::Sp1InstructionHandler, program::Sp1Program,
};

pub fn build_elf_path(guest_path: &str, build_args: BuildArgs) -> String {
    sp1_helper::build_program_with_args(guest_path, build_args.clone());
    let program_dir = std::path::Path::new(guest_path);
    let metadata_file = program_dir.join("Cargo.toml");
    let mut metadata_cmd = cargo_metadata::MetadataCommand::new();
    let metadata = metadata_cmd.manifest_path(metadata_file).exec().unwrap();
    let target_elf_paths = generate_elf_paths(&metadata, Some(&build_args))
        .expect("failed to collect target ELF paths");
    // For now, take the first elf path
    // TODO: add a filter input argument and assert only one elf is left after filtering
    let out_path = target_elf_paths[0].1.clone();

    out_path.to_string()
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
    BuildArgs {
        rustflags: vec!["-C".to_string(), "link-arg=--emit-relocs".to_string()],
        build_target: DEFAULT_TARGET_64.to_string(),
        ..Default::default()
    }
}

pub struct CompiledProgram {
    pub basic_blocks: Vec<BasicBlock<Sp1Instruction>>,
}

impl CompiledProgram {
    pub fn new(original_program: Program, labels: &BTreeSet<u64>) -> Self {
        let basic_blocks = collect_basic_blocks::<Sp1ApcAdapter>(
            &Sp1Program(original_program),
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

    use crate::{autoprecompiles::instruction_handler::Sp1InstructionHandler, utils::setup_logger};

    #[test]
    fn test_extract_machine() {
        setup_logger();
        let instruction_handler = Sp1InstructionHandler::<BabyBear>::new();
        let airs = instruction_handler.airs();
        // TODO: Use `render(bus_map)` instead of `to_string()`, once the bus map is complete.
        let rendered = airs
            .map(|(instruction_type, air)| format!("# {instruction_type:?}\n{air}"))
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
    use sp1_core_executor::{Instruction, Opcode};

    use crate::{
        autoprecompiles::{
            adapter::Sp1ApcAdapter, bus_interaction_handler::Sp1BusInteractionHandler,
            bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler,
        },
        utils::setup_logger,
    };

    const GUEST_FIBONACCI: &str = "../../test-artifacts/programs/fibonacci";

    fn compile(basic_block: Vec<Instruction>) -> String {
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
            // render() does not work, because not all buses are in the bus map yet.
            .to_string();
        tracing::info!("Original AIR:\n{original_air}");

        let apc = build::<Sp1ApcAdapter>(block, vm_config, degree_bound, 1234, None).unwrap();
        apc.machine.render(&sp1_bus_map())
    }

    #[test]
    #[should_panic]
    fn test_add() {
        setup_logger();
        let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 0, 5, false, true)];
        let rendered = compile(basic_block);
        tracing::info!("{rendered}");
    }

    #[test]
    // #[should_panic = "get labels"]
    fn test_collect_basic_blocks() {
        setup_logger();

        let compiled_program = compile_exe(GUEST_FIBONACCI);

        // For now, just assert the number of basic blocks produced.
        assert_eq!(compiled_program.basic_blocks.len(), 1565);
    }
}
