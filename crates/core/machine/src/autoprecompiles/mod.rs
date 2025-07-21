pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod program;

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
    use powdr_autoprecompiles::{build, BasicBlock, DegreeBound, InstructionHandler, VmConfig};
    use sp1_core_executor::{Instruction, Opcode};

    use crate::{
        autoprecompiles::{
            adapter::Sp1ApcAdapter,
            bus_interaction_handler::Sp1BusInteractionHandler,
            bus_map::sp1_bus_map,
            instruction::Sp1Instruction,
            instruction_machine_handler::{air_id_to_opcodes, Sp1InstructionHandler},
            program::Sp1Program,
        },
        riscv::RiscvAir,
        utils::setup_logger,
    };

    fn detect_basic_blocks(
        program: Program,
        jumpdest: BTreeSet<u64>,
    ) -> Vec<BasicBlock<Sp1Instruction>> {
        collect_basic_blocks::<Sp1ApcAdapter>(
            &Sp1Program(program),
            &jumpdest,
            &Sp1InstructionHandler::new(),
        )
    }

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
        // let instructions = vec![];
        let fibo_path = "../../test-artifacts/programs/fibonacci";
        // let output_directory = "../../test-artifacts/programs/fibonacci".to_string();
        sp1_helper::build_program_with_args(
            fibo_path,
            BuildArgs {
                rustflags: vec!["-C".to_string(), "link-arg=--emit-relocs".to_string()],
                // ... set other fields as needed, or use ..Default::default()
                // output_directory: Some(output_directory),
                ..Default::default()
            },
        );
        // let sp1_elf = test_artifacts::FIBONACCI_ELF;
        let sp1_elf = std::fs::read("../../test-artifacts/programs/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/fibonacci-program-tests").unwrap();
        println!("sp1_elf read successfully");
        
        let powdr_elf_labels = powdr_riscv_elf::rv64::load_elf_from_buffer_rv64(&sp1_elf);
        // let text_labels: BTreeSet<_> = powdr_elf.text_labels().iter().map(|&x| x as u64).collect();
        let program = Program::from(&sp1_elf).unwrap();
        let basic_blocks = detect_basic_blocks(program, powdr_elf_labels.text_labels);

        basic_blocks.iter()
            .for_each(|bb| println!("{:?}", bb));

        // assert!(basic_blocks.is_empty());
    }
}
