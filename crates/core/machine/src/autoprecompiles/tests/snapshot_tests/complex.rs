use sp1_core_executor::{Instruction, Opcode};

use crate::utils::setup_logger;

fn assert_machine_output(basic_block: Vec<Instruction>, test_name: &str) {
    crate::autoprecompiles::tests::snapshot_tests::assert_machine_output(
        basic_block,
        "complex",
        test_name,
    );
}

#[test]
fn test_two_ld() {
    setup_logger();
    // Used to trigger a failure of `check_register_operation_consistency`
    let basic_block = vec![
        Instruction::new(Opcode::LD, 12, 10, 0, false, true),
        Instruction::new(Opcode::LD, 10, 12, 8, false, true),
    ];
    assert_machine_output(basic_block, "two_ld")
}

#[test]
fn test_memory_optimizer() {
    setup_logger();
    let basic_block = vec![
        // x1 <- x2
        Instruction::new(Opcode::ADDI, 1, 2, 0, false, true),
        // x1 <- x1 + x2
        Instruction::new(Opcode::ADD, 1, 1, 2, false, false),
    ];
    assert_machine_output(basic_block, "memory_optimizer");
}
