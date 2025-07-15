use std::collections::HashMap;

use crate::{autoprecompiles::air_to_symbolic_machine::air_to_symbolic_machine, riscv::RiscvAir};
use itertools::Itertools;
use powdr_autoprecompiles::{
    InstructionMachineHandler, SymbolicInstructionStatement, SymbolicMachine,
};
use powdr_number::FieldElement;
use slop_algebra::PrimeField32;
use sp1_core_executor::{Opcode, RiscvAirId};
use sp1_stark::air::MachineAir;

#[derive(Default)]
pub struct InstructionAirs<P> {
    airs: Vec<SymbolicMachine<P>>,
    instruction_to_air_idx: HashMap<(usize, bool), usize>,
}

impl<P: FieldElement> InstructionAirs<P> {
    pub fn add<F: PrimeField32>(&mut self, riscv_air: &RiscvAir<F>) {
        let opcodes = air_id_to_opcodes(riscv_air.id());

        if opcodes.is_empty() {
            // Not an instruction AIR.
            return;
        }
        let machine = match air_to_symbolic_machine::<F, P>(riscv_air) {
            Ok(machine) => machine,
            Err(err) => {
                tracing::warn!("Failed to convert {} to symbolic machine: {err}", riscv_air.name());
                return;
            }
        };

        let opcodes_and_is_x0 = if is_load_air(&riscv_air.id()) {
            // For loads, LoadX0 handles all loads if rd == x0.
            let is_load_x0 = riscv_air.id() == RiscvAirId::LoadX0;
            opcodes.into_iter().map(|opcode| (opcode, is_load_x0)).collect_vec()
        } else {
            // For all other instructions, the value of rd does not matter.
            opcodes.into_iter().cartesian_product([false, true]).collect_vec()
        };

        let idx = self.airs.len();
        self.airs.push(machine);
        for (opcode, is_x0) in opcodes_and_is_x0 {
            self.instruction_to_air_idx.insert((opcode as usize, is_x0), idx);
        }
    }

    pub fn air_count(&self) -> usize {
        self.airs.len()
    }
}

fn air_id_to_opcodes(air_id: RiscvAirId) -> Vec<Opcode> {
    // Instruction -> AIR mapping from:
    // https://github.com/succinctlabs/sp1-wip/blob/1ec34e044ead850ed90deb1b66771eb0cfc8dc7e/crates/core/executor/src/executor.rs#L2552
    match air_id {
        RiscvAirId::Add => vec![Opcode::ADD],
        RiscvAirId::Addi => vec![Opcode::ADDI],
        RiscvAirId::Sub => vec![Opcode::SUB],
        RiscvAirId::Bitwise => vec![Opcode::XOR, Opcode::OR, Opcode::AND],
        RiscvAirId::DivRem => vec![
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::DIVUW,
            Opcode::REMW,
            Opcode::REMUW,
        ],
        RiscvAirId::Lt => vec![Opcode::SLT, Opcode::SLTU],
        RiscvAirId::Mul => {
            vec![Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU, Opcode::MULW]
        }
        RiscvAirId::ShiftLeft => vec![Opcode::SLL, Opcode::SLLW],
        RiscvAirId::ShiftRight => vec![Opcode::SRL, Opcode::SRA, Opcode::SRLW, Opcode::SRAW],
        RiscvAirId::Branch => {
            vec![Opcode::BEQ, Opcode::BNE, Opcode::BLT, Opcode::BGE, Opcode::BLTU, Opcode::BGEU]
        }
        RiscvAirId::Jal => vec![Opcode::JAL],
        RiscvAirId::Jalr => vec![Opcode::JALR],
        RiscvAirId::UType => vec![Opcode::LUI, Opcode::AUIPC],
        RiscvAirId::LoadByte => vec![Opcode::LB, Opcode::LBU],
        RiscvAirId::LoadHalf => vec![Opcode::LH, Opcode::LHU],
        RiscvAirId::LoadWord => vec![Opcode::LW, Opcode::LWU],
        RiscvAirId::LoadDouble => vec![Opcode::LD],
        // Note that for load instructions, the opcode -> AIR mapping is not injective.
        RiscvAirId::LoadX0 => vec![
            Opcode::LB,
            Opcode::LBU,
            Opcode::LH,
            Opcode::LHU,
            Opcode::LW,
            Opcode::LWU,
            Opcode::LD,
        ],
        RiscvAirId::StoreByte => vec![Opcode::SB],
        RiscvAirId::StoreHalf => vec![Opcode::SH],
        RiscvAirId::StoreWord => vec![Opcode::SW],
        RiscvAirId::StoreDouble => vec![Opcode::SD],
        RiscvAirId::SyscallInstrs => vec![Opcode::ECALL],
        _ => Default::default(),
    }
}

fn is_load_air(air_id: &RiscvAirId) -> bool {
    matches!(
        air_id,
        RiscvAirId::LoadByte
            | RiscvAirId::LoadHalf
            | RiscvAirId::LoadWord
            | RiscvAirId::LoadDouble
            | RiscvAirId::LoadX0
    )
}

impl<P: FieldElement> InstructionMachineHandler<P> for InstructionAirs<P> {
    fn get_instruction_air(
        &self,
        instruction: &SymbolicInstructionStatement<P>,
    ) -> Option<&SymbolicMachine<P>> {
        // op_a_0 is the third last instruction column:
        // https://github.com/succinctlabs/sp1-wip/blob/1ec34e044ead850ed90deb1b66771eb0cfc8dc7e/crates/core/machine/src/cpu/columns/instruction.rs#L57
        // which is followed by 3 more fields:
        // https://github.com/succinctlabs/sp1-wip/blob/1ec34e044ead850ed90deb1b66771eb0cfc8dc7e/crates/core/machine/src/air/program.rs#L24

        let op_a_0 = instruction.args[instruction.args.len() - 6];
        assert!(op_a_0.is_zero() || op_a_0.is_one(), "Expected op_a_0 to be 0 or 1, got {op_a_0}");
        let op_a_0 = op_a_0.is_one();
        let opcode = instruction.opcode as usize;
        let idx = self.instruction_to_air_idx.get(&(opcode, op_a_0))?;
        Some(&self.airs[*idx])
    }
}
