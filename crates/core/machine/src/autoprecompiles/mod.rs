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

use powdr_autoprecompiles::{
    adapter::AdapterApc,
    blocks::{collect_basic_blocks, generate_apcs_with_pgo},
    DegreeBound, PgoConfig, PowdrConfig, VmConfig,
};
use sp1_build::{generate_elf_paths, BuildArgs, DEFAULT_TARGET_64};
use sp1_core_executor::Program;
use std::collections::BTreeSet;

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, bus_interaction_handler::Sp1BusInteractionHandler,
    bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler, program::Sp1Program,
};

// TODO: Is this correct?
const SP1_DEGREE_BOUND: usize = 3;
const DEFAULT_DEGREE_BOUND: DegreeBound =
    DegreeBound { identities: SP1_DEGREE_BOUND, bus_interactions: SP1_DEGREE_BOUND - 1 };

// TODO: Is this ok?
const POWDR_OPCODE: usize = 0x10ff;

pub fn default_powdr_sp1_config(apc: u64, skip: u64) -> PowdrConfig {
    PowdrConfig::new(apc, skip, DEFAULT_DEGREE_BOUND, POWDR_OPCODE)
}

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

pub fn compile_exe_with_elf(
    elf: &[u8],
    config: PowdrConfig,
    pgo_config: PgoConfig,
) -> CompiledProgram {
    let labels = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf);

    let original_program = Program::from(elf).unwrap();

    CompiledProgram::new(original_program, &labels.jumpdests, config, pgo_config)
}

pub fn compile_exe(
    guest_path: &str,
    config: PowdrConfig,
    pgo_config: PgoConfig,
) -> CompiledProgram {
    let build_args = powdr_default_build_args();
    let elf_path = build_elf_path(guest_path, build_args);
    let elf = std::fs::read(elf_path).unwrap();

    compile_exe_with_elf(&elf, config, pgo_config)
}

pub fn powdr_default_build_args() -> BuildArgs {
    BuildArgs { build_target: DEFAULT_TARGET_64.to_string(), ..Default::default() }
}

pub struct CompiledProgram {
    pub apcs: Vec<AdapterApc<Sp1ApcAdapter>>,
}

impl CompiledProgram {
    pub fn new(
        original_program: Program,
        labels: &BTreeSet<u64>,
        config: PowdrConfig,
        pgo_config: PgoConfig,
    ) -> Self {
        let program = Sp1Program::from(original_program);

        let airs = Sp1InstructionHandler::new();

        let vm_config = VmConfig {
            instruction_handler: &airs,
            // TODO: update bus interaction handler constructor once complete
            bus_interaction_handler: Sp1BusInteractionHandler::default(),
            bus_map: sp1_bus_map(),
        };

        let max_total_apc_columns: Option<usize> = match pgo_config {
            // TODO: not sure if we need to limit max_total_columns at all
            // If yes, need to subtract non-APC SP1 columns from it
            PgoConfig::Cell(_, max_total_columns) => max_total_columns,
            PgoConfig::Instruction(_) | PgoConfig::None => None,
        };

        // Collect basic blocks
        let blocks = collect_basic_blocks::<Sp1ApcAdapter>(&program, labels, &airs);
        tracing::info!("Got {} basic blocks from `collect_basic_blocks`", blocks.len());

        // Generate APC
        let apcs = generate_apcs_with_pgo::<Sp1ApcAdapter>(
            blocks,
            &config,
            max_total_apc_columns,
            pgo_config,
            vm_config,
        );

        let apcs = apcs.into_iter().map(|(apc, _)| apc).collect::<Vec<_>>();

        // TODO: cater `CompiledProgram` to what's needed for execution
        Self { apcs }
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
    use powdr_autoprecompiles::{build, BasicBlock, InstructionHandler, VmConfig};
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

    fn assert_machine_output(basic_block: Vec<Instruction>, test_name: &str) {
        let vm_config = VmConfig {
            instruction_handler: &Sp1InstructionHandler::new(),
            bus_interaction_handler: Sp1BusInteractionHandler::default(),
            bus_map: sp1_bus_map(),
        };
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

        let apc =
            build::<Sp1ApcAdapter>(block, vm_config, DEFAULT_DEGREE_BOUND, 1234, None).unwrap();
        let actual = apc.machine.to_string();

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
}

#[cfg(test)]
mod compile_program_tests {
    use super::*;
    use crate::utils::setup_logger;
    use powdr_autoprecompiles::InstructionHandler;

    const GUEST_FIBONACCI: &str = "../../test-artifacts/programs/fibonacci";
    const APC: u64 = 10;
    const APC_SKIP: u64 = 0;

    #[test]
    fn test_compile_program() {
        let config = default_powdr_sp1_config(APC, APC_SKIP);
        let pgo_config = PgoConfig::None;
        let _ = compile_exe(GUEST_FIBONACCI, config, pgo_config);
    }

    #[test]
    fn test_collect_basic_blocks() {
        setup_logger();

        let build_args = powdr_default_build_args();
        let elf_path = build_elf_path(GUEST_FIBONACCI, build_args);
        let elf = std::fs::read(elf_path).unwrap();

        let sp1_program = Sp1Program::from(Program::from(&elf).unwrap());
        let jumpdest_set = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(&elf).jumpdests;
        let instruction_handler = Sp1InstructionHandler::<slop_baby_bear::BabyBear>::new();

        // Check total number of basic blocks produced
        let basic_blocks = collect_basic_blocks::<Sp1ApcAdapter>(
            &sp1_program,
            &jumpdest_set,
            &instruction_handler,
        );
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
