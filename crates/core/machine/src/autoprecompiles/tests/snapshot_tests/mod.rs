use powdr_autoprecompiles::{build, evaluation::evaluate_apc, BasicBlock};
use pretty_assertions::assert_eq;
use slop_baby_bear::BabyBear;
use sp1_core_executor::Instruction;
use std::{fs, path::Path};

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler,
    sp1_vm_config, DEFAULT_DEGREE_BOUND,
};

mod complex;
mod single_instructions;

fn assert_machine_output(basic_block: Vec<Instruction>, module_name: &str, test_name: &str) {
    let instruction_handler = Sp1InstructionHandler::<BabyBear>::new();
    let vm_config = sp1_vm_config(&instruction_handler);
    let block = BasicBlock {
        start_pc: 0,
        statements: basic_block.iter().cloned().map(Into::into).collect(),
    };

    let apc = build::<Sp1ApcAdapter>(block.clone(), vm_config, DEFAULT_DEGREE_BOUND, None).unwrap();

    let basic_block_str =
        basic_block.iter().map(|inst| format!("  {inst:?}")).collect::<Vec<_>>().join("\n");
    let evaluation = evaluate_apc(&block.statements, &instruction_handler, &apc.machine);
    let actual = format!(
        "Instructions:\n{basic_block_str}\n\n{}\n\n{}",
        evaluation,
        apc.machine.render(&sp1_bus_map())
    );

    let expected_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("apc_snapshots")
        .join(module_name)
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
