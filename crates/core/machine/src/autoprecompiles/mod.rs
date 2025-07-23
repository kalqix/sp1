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
    use powdr_autoprecompiles::{build, BasicBlock, DegreeBound, VmConfig};
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
        let basic_block_str =
            basic_block.iter().map(|inst| format!("//   {inst:?}")).collect::<Vec<_>>().join("\n");

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

        let apc = build::<Sp1ApcAdapter>(block, vm_config, degree_bound, 1234, None).unwrap();
        let actual = format!(
            "// APC for basic block:\n{basic_block_str}\n//\n{}",
            apc.machine.render(&sp1_bus_map())
        );

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
    fn test_addi() {
        setup_logger();
        let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 0, 5, false, true)];
        assert_machine_output(basic_block, "addi")
    }

    #[test]
    fn test_add() {
        let basic_block = vec![Instruction::new(Opcode::ADD, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "add")
    }

    #[test]
    fn test_sub() {
        let basic_block = vec![Instruction::new(Opcode::SUB, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "sub")
    }

    #[test]
    fn test_xor() {
        let basic_block = vec![Instruction::new(Opcode::XOR, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "xor")
    }

    #[test]
    fn test_or() {
        let basic_block = vec![Instruction::new(Opcode::OR, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "or")
    }

    #[test]
    fn test_and() {
        let basic_block = vec![Instruction::new(Opcode::AND, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "and")
    }

    #[test]
    fn test_sll() {
        let basic_block = vec![Instruction::new(Opcode::SLL, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "sll")
    }

    #[test]
    fn test_srl() {
        let basic_block = vec![Instruction::new(Opcode::SRL, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "srl")
    }

    #[test]
    fn test_sra() {
        let basic_block = vec![Instruction::new(Opcode::SRA, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "sra")
    }

    #[test]
    fn test_slt() {
        let basic_block = vec![Instruction::new(Opcode::SLT, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "slt")
    }

    #[test]
    fn test_sltu() {
        let basic_block = vec![Instruction::new(Opcode::SLTU, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "sltu")
    }

    #[test]
    fn test_mul() {
        let basic_block = vec![Instruction::new(Opcode::MUL, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "mul")
    }

    #[test]
    fn test_mulh() {
        let basic_block = vec![Instruction::new(Opcode::MULH, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "mulh")
    }

    #[test]
    fn test_mulhu() {
        let basic_block = vec![Instruction::new(Opcode::MULHU, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "mulhu")
    }

    #[test]
    fn test_mulhsu() {
        let basic_block = vec![Instruction::new(Opcode::MULHSU, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "mulhsu")
    }

    #[test]
    fn test_div() {
        let basic_block = vec![Instruction::new(Opcode::DIV, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "div")
    }

    #[test]
    fn test_divu() {
        let basic_block = vec![Instruction::new(Opcode::DIVU, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "divu")
    }

    #[test]
    fn test_rem() {
        let basic_block = vec![Instruction::new(Opcode::REM, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "rem")
    }

    #[test]
    fn test_remu() {
        let basic_block = vec![Instruction::new(Opcode::REMU, 1, 2, 3, false, true)];
        assert_machine_output(basic_block, "remu")
    }

    #[test]
    fn test_lb() {
        let basic_block = vec![Instruction::new(Opcode::LB, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "lb")
    }

    #[test]
    fn test_lh() {
        let basic_block = vec![Instruction::new(Opcode::LH, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "lh")
    }

    #[test]
    fn test_lw() {
        let basic_block = vec![Instruction::new(Opcode::LW, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "lw")
    }

    #[test]
    fn test_lbu() {
        let basic_block = vec![Instruction::new(Opcode::LBU, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "lbu")
    }

    #[test]
    fn test_lhu() {
        let basic_block = vec![Instruction::new(Opcode::LHU, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "lhu")
    }

    #[test]
    fn test_sb() {
        let basic_block = vec![Instruction::new(Opcode::SB, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "sb")
    }

    #[test]
    fn test_sh() {
        let basic_block = vec![Instruction::new(Opcode::SH, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "sh")
    }

    #[test]
    fn test_sw() {
        let basic_block = vec![Instruction::new(Opcode::SW, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "sw")
    }

    #[test]
    fn test_beq() {
        let basic_block = vec![Instruction::new(Opcode::BEQ, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "beq")
    }

    #[test]
    fn test_bne() {
        let basic_block = vec![Instruction::new(Opcode::BNE, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "bne")
    }

    #[test]
    fn test_blt() {
        let basic_block = vec![Instruction::new(Opcode::BLT, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "blt")
    }

    #[test]
    fn test_bge() {
        let basic_block = vec![Instruction::new(Opcode::BGE, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "bge")
    }

    #[test]
    fn test_bltu() {
        let basic_block = vec![Instruction::new(Opcode::BLTU, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "bltu")
    }

    #[test]
    fn test_bgeu() {
        let basic_block = vec![Instruction::new(Opcode::BGEU, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "bgeu")
    }

    #[test]
    fn test_jal() {
        let basic_block = vec![Instruction::new(Opcode::JAL, 1, 0, 100, false, true)];
        assert_machine_output(basic_block, "jal")
    }

    #[test]
    fn test_jalr() {
        let basic_block = vec![Instruction::new(Opcode::JALR, 1, 2, 100, false, true)];
        assert_machine_output(basic_block, "jalr")
    }

    #[test]
    fn test_auipc() {
        let basic_block = vec![Instruction::new(Opcode::AUIPC, 1, 0, 0x12345, false, true)];
        assert_machine_output(basic_block, "auipc")
    }

    #[test]
    fn test_lui() {
        let basic_block = vec![Instruction::new(Opcode::LUI, 1, 0, 0x12345, false, true)];
        assert_machine_output(basic_block, "lui")
    }
}

#[cfg(test)]
mod basic_block_detection_tests {
    use super::*;
    use powdr_autoprecompiles::InstructionHandler;
    use pretty_assertions::assert_eq;

    use crate::{autoprecompiles::instruction_handler::Sp1InstructionHandler, utils::setup_logger};
    const GUEST_FIBONACCI: &str = "../../test-artifacts/programs/fibonacci";

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
