use sp1_core_executor::{Instruction, Opcode};

use crate::utils::setup_logger;

fn assert_machine_output(basic_block: Vec<Instruction>, test_name: &str) {
    crate::autoprecompiles::tests::snapshot_tests::assert_machine_output(
        basic_block,
        "pseudo_instructions",
        test_name,
    );
}

#[test]
fn test_mv() {
    setup_logger();
    // mv rd, rs1 => addi rd, rs, 0
    let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 30, 0, false, true)];
    assert_machine_output(basic_block, "mv")
}
