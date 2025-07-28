use sp1_core_executor::{Instruction, Opcode};

use crate::utils::setup_logger;

fn assert_machine_output(basic_block: Vec<Instruction>, test_name: &str) {
    crate::autoprecompiles::tests::snapshot_tests::assert_machine_output(
        basic_block,
        "single_instructions",
        test_name,
    );
}

#[test]
fn test_addi() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 0, 5, false, true)];
    assert_machine_output(basic_block, "addi")
}

#[test]
fn test_add() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::ADD, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "add")
}

#[test]
fn test_sub() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SUB, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "sub")
}

#[test]
fn test_xor() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::XOR, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "xor")
}

#[test]
fn test_or() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::OR, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "or")
}

#[test]
fn test_and() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::AND, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "and")
}

#[test]
fn test_sll() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SLL, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "sll")
}

#[test]
fn test_srl() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SRL, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "srl")
}

#[test]
fn test_sra() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SRA, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "sra")
}

#[test]
fn test_slt() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SLT, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "slt")
}

#[test]
fn test_sltu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SLTU, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "sltu")
}

#[test]
fn test_sltui() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SLTU, 1, 2, 3, false, true)];
    assert_machine_output(basic_block, "sltui")
}

#[test]
fn test_mul() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::MUL, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "mul")
}

#[test]
fn test_mulh() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::MULH, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "mulh")
}

#[test]
fn test_mulhu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::MULHU, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "mulhu")
}

#[test]
fn test_mulhsu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::MULHSU, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "mulhsu")
}

#[test]
fn test_div() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::DIV, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "div")
}

#[test]
fn test_divu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::DIVU, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "divu")
}

#[test]
fn test_rem() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::REM, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "rem")
}

#[test]
fn test_remu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::REMU, 1, 2, 3, false, false)];
    assert_machine_output(basic_block, "remu")
}

#[test]
fn test_lb() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LB, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "lb")
}

#[test]
fn test_lh() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LH, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "lh")
}

#[test]
fn test_lw() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LW, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "lw")
}

#[test]
fn test_lbu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LBU, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "lbu")
}

#[test]
fn test_lhu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LHU, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "lhu")
}

#[test]
fn test_sb() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SB, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "sb")
}

#[test]
fn test_sh() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SH, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "sh")
}

#[test]
fn test_sw() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::SW, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "sw")
}

#[test]
fn test_beq() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BEQ, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "beq")
}

#[test]
fn test_bne() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BNE, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "bne")
}

#[test]
fn test_blt() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BLT, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "blt")
}

#[test]
fn test_bge() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BGE, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "bge")
}

#[test]
fn test_bltu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BLTU, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "bltu")
}

#[test]
fn test_bgeu() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::BGEU, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "bgeu")
}

#[test]
fn test_jal() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::JAL, 1, 0, 100, true, true)];
    assert_machine_output(basic_block, "jal")
}

#[test]
fn test_jalr() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::JALR, 1, 2, 100, false, true)];
    assert_machine_output(basic_block, "jalr")
}

#[test]
fn test_auipc() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::AUIPC, 1, 0, 0x12345, true, true)];
    assert_machine_output(basic_block, "auipc")
}

#[test]
fn test_lui() {
    setup_logger();
    let basic_block = vec![Instruction::new(Opcode::LUI, 1, 0, 0x12345, true, true)];
    assert_machine_output(basic_block, "lui")
}
