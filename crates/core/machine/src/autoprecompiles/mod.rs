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
    use std::{fs, path::Path};

    use powdr_autoprecompiles::{build, BasicBlock, DegreeBound, InstructionHandler, VmConfig};
    use pretty_assertions::assert_eq;
    use sp1_core_executor::{Instruction, Opcode};

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
