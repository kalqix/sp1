use powdr_autoprecompiles::{blocks::BasicBlock, build, evaluation::evaluate_apc};
use pretty_assertions::assert_eq;
use sp1_core_executor::Instruction;
use sp1_primitives::SP1Field;
use std::{fs, path::Path};

use crate::autoprecompiles::{
    adapter::Sp1ApcAdapter, bus_map::sp1_bus_map, instruction_handler::Sp1InstructionHandler,
    sp1_vm_config, DEFAULT_DEGREE_BOUND,
};

mod complex;
mod pseudo_instructions;
mod single_instructions;

fn assert_machine_output(basic_block: Vec<Instruction>, module_name: &str, test_name: &str) {
    let instruction_handler = Sp1InstructionHandler::<SP1Field>::new();
    let vm_config = sp1_vm_config(&instruction_handler);
    let block = BasicBlock {
        start_pc: 0,
        statements: basic_block.iter().cloned().map(Into::into).collect(),
    };

    let apc = build::<Sp1ApcAdapter>(block.clone(), vm_config, DEFAULT_DEGREE_BOUND, None).unwrap();

    let basic_block_str = basic_block
        .iter()
        .enumerate()
        .map(|(i, inst)| format!("  {i:>3}: {inst:?}"))
        .collect::<Vec<_>>()
        .join("\n");
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

    let expected = fs::read_to_string(&expected_path).ok();
    let should_update = expected.is_none()
        || std::env::var("UPDATE_EXPECT").map(|v| v.as_str() == "1").unwrap_or(false);

    if should_update {
        // Write the new expected output to the file
        fs::create_dir_all(expected_path.parent().unwrap()).unwrap();
        fs::write(&expected_path, actual).unwrap();

        tracing::info!(
            "Expected output for `{test_name}` was updated. Re-run the test to confirm."
        );
    } else {
        assert_eq!(
            expected.unwrap().trim(),
            actual.trim(),
            "The output of `{test_name}` does not match the expected output. \
             To re-generate the expected output, run with `UPDATE_EXPECT=1`."
        );
    }
}
