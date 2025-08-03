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

#[test]
fn test_not() {
    setup_logger();
    // not rd, rs1 => xori rd, rs1, -1
    // -1 in two's complement is all 1s (0xFFFFFFFFFFFFFFFF)
    let basic_block = vec![Instruction::new(Opcode::XOR, 8, 5, 0xFFFFFFFFFFFFFFFF, false, true)];
    assert_machine_output(basic_block, "not")
}

#[test]
fn test_neg() {
    setup_logger();
    // neg rd, rs1 => sub rd, x0, rs1
    let basic_block = vec![Instruction::new(Opcode::SUB, 8, 0, 5, false, false)];
    assert_machine_output(basic_block, "neg")
}

#[test]
fn test_seqz() {
    setup_logger();
    // seqz rd, rs1 => sltiu rd, rs1, 1
    let basic_block = vec![Instruction::new(Opcode::SLTU, 8, 5, 1, false, true)];
    assert_machine_output(basic_block, "seqz")
}

#[test]
fn test_snez() {
    setup_logger();
    // snez rd, rs1 => sltu rd, x0, rs1
    let basic_block = vec![Instruction::new(Opcode::SLTU, 8, 0, 5, false, false)];
    assert_machine_output(basic_block, "snez")
}

#[test]
fn test_sltz() {
    setup_logger();
    // sltz rd, rs1 => slt rd, rs1, x0
    let basic_block = vec![Instruction::new(Opcode::SLT, 8, 5, 0, false, false)];
    assert_machine_output(basic_block, "sltz")
}

#[test]
fn test_sgtz() {
    setup_logger();
    // sgtz rd, rs1 => slt rd, x0, rs1
    let basic_block = vec![Instruction::new(Opcode::SLT, 8, 0, 5, false, false)];
    assert_machine_output(basic_block, "sgtz")
}

#[test]
fn test_beqz() {
    setup_logger();
    // beqz rs1, offset => beq rs1, x0, offset
    let basic_block = vec![Instruction::new(Opcode::BEQ, 5, 0, 8, false, true)];
    assert_machine_output(basic_block, "beqz")
}

#[test]
fn test_bnez() {
    setup_logger();
    // bnez rs1, offset => bne rs1, x0, offset
    let basic_block = vec![Instruction::new(Opcode::BNE, 5, 0, 8, false, true)];
    assert_machine_output(basic_block, "bnez")
}

#[test]
fn test_blez() {
    setup_logger();
    // blez rs1, offset => bge x0, rs1, offset
    let basic_block = vec![Instruction::new(Opcode::BGE, 0, 5, 8, false, true)];
    assert_machine_output(basic_block, "blez")
}

#[test]
fn test_bgez() {
    setup_logger();
    // bgez rs1, offset => bge rs1, x0, offset
    let basic_block = vec![Instruction::new(Opcode::BGE, 5, 0, 8, false, true)];
    assert_machine_output(basic_block, "bgez")
}

#[test]
fn test_bltz() {
    setup_logger();
    // bltz rs1, offset => blt rs1, x0, offset
    let basic_block = vec![Instruction::new(Opcode::BLT, 5, 0, 8, false, true)];
    assert_machine_output(basic_block, "bltz")
}

#[test]
fn test_bgtz() {
    setup_logger();
    // bgtz rs1, offset => blt x0, rs1, offset
    let basic_block = vec![Instruction::new(Opcode::BLT, 0, 5, 8, false, true)];
    assert_machine_output(basic_block, "bgtz")
}

#[test]
fn test_j() {
    setup_logger();
    // j offset => jal x0, offset
    let basic_block = vec![Instruction::new(Opcode::JAL, 0, 0, 8, true, true)];
    assert_machine_output(basic_block, "j")
}

#[test]
fn test_jr() {
    setup_logger();
    // jr rs1 => jalr x0, rs1, 0
    let basic_block = vec![Instruction::new(Opcode::JALR, 0, 5, 0, false, true)];
    assert_machine_output(basic_block, "jr")
}

#[test]
fn test_ret() {
    setup_logger();
    // ret => jalr x0, x1, 0
    let basic_block = vec![Instruction::new(Opcode::JALR, 0, 1, 0, false, true)];
    assert_machine_output(basic_block, "ret")
}
