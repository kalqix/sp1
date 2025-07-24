use std::collections::BTreeMap;

use crate::{
    autoprecompiles::{
        air_to_symbolic_machine::{air_to_symbolic_machine, densify_ids, sort_memory_interactions},
        instruction::Sp1Instruction,
    },
    riscv::RiscvAir,
};
use itertools::Itertools;
use powdr_autoprecompiles::{InstructionHandler, SymbolicMachine};
use slop_algebra::PrimeField32;
use sp1_core_executor::{Opcode, RiscvAirId};
use sp1_stark::air::MachineAir;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstructionType {
    /// An instruction that is not a load to X0, represented by its opcode.
    NonLoadX0(Opcode),
    /// A load instruction that is a load to x0.
    LoadX0,
}

#[derive(Default)]
pub struct Sp1InstructionHandler<F> {
    /// All instruction AIRs.
    airs: Vec<SymbolicMachine<F>>,
    /// Maps (opcode, op_a_0) to the index of the corresponding AIR in `airs`.
    /// (Using BTreeMap for determinism of [Sp1InstructionHandler::airs].)
    instruction_to_air_idx: BTreeMap<InstructionType, usize>,
}

impl<F: PrimeField32> Sp1InstructionHandler<F> {
    pub fn new() -> Self {
        let mut handler = Self::default();
        for air in RiscvAir::airs() {
            handler.add(&air);
        }
        handler
    }

    pub fn add(&mut self, riscv_air: &RiscvAir<F>) {
        let opcodes = air_id_to_opcodes(riscv_air.id());

        if opcodes.is_empty() {
            // Not an instruction AIR.
            return;
        }
        let machine = match air_to_symbolic_machine(riscv_air) {
            Ok(machine) => machine,
            Err(err) => {
                tracing::warn!("Failed to convert {} to symbolic machine: {err}", riscv_air.name());
                return;
            }
        };
        // In some machines, not all references are used, so we densify the IDs.
        // TODO: This will likely complicate witgen, maybe it better to relax the assumption in
        // powdr that IDs have to be dense?
        let machine = densify_ids(machine);
        let machine = sort_memory_interactions(machine);

        let instruction_types =
            if is_load_air(&riscv_air.id()) && riscv_air.id() == RiscvAirId::LoadX0 {
                // For loads, LoadX0 handles all loads if rd == x0.
                vec![InstructionType::LoadX0]
            } else {
                opcodes.into_iter().map(InstructionType::NonLoadX0).collect_vec()
            };

        let idx = self.airs.len();
        self.airs.push(machine);
        for instruction_type in instruction_types {
            self.instruction_to_air_idx.insert(instruction_type, idx);
        }
    }

    pub fn air_count(&self) -> usize {
        self.airs.len()
    }

    #[cfg(test)]
    pub fn airs(&self) -> impl Iterator<Item = (InstructionType, &SymbolicMachine<F>)> {
        self.instruction_to_air_idx
            .iter()
            .map(|(instruction_type, idx)| (instruction_type.clone(), &self.airs[*idx]))
    }
}

fn air_id_to_opcodes(air_id: RiscvAirId) -> Vec<Opcode> {
    // Instruction -> AIR mapping inspired from:
    // https://github.com/succinctlabs/sp1-wip/blob/1ec34e044ead850ed90deb1b66771eb0cfc8dc7e/crates/core/executor/src/executor.rs#L2552
    match air_id {
        RiscvAirId::Add => vec![Opcode::ADD],
        RiscvAirId::Addi => vec![Opcode::ADDI],
        RiscvAirId::Addw => vec![Opcode::ADDW],
        RiscvAirId::Sub => vec![Opcode::SUB],
        RiscvAirId::Subw => vec![Opcode::SUBW],
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

fn is_load_opcode(opcode: Opcode) -> bool {
    matches!(
        opcode,
        Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW | Opcode::LWU | Opcode::LD
    )
}

impl<F: PrimeField32> InstructionHandler<F, Sp1Instruction> for Sp1InstructionHandler<F> {
    fn get_instruction_air(&self, instruction: &Sp1Instruction) -> Option<&SymbolicMachine<F>> {
        let instruction_type = if is_load_opcode(instruction.0.opcode)
            && instruction.0.op_a == sp1_core_executor::Register::X0 as u8
        {
            InstructionType::LoadX0
        } else {
            InstructionType::NonLoadX0(instruction.0.opcode)
        };

        let idx = self.instruction_to_air_idx.get(&instruction_type)?;
        Some(&self.airs[*idx])
    }

    fn is_allowed(&self, instruction: &Sp1Instruction) -> bool {
        !matches!(instruction.0.opcode, Opcode::EBREAK | Opcode::ECALL | Opcode::UNIMP)
    }

    fn is_branching(&self, instruction: &Sp1Instruction) -> bool {
        // We define the branch opcodes manually
        matches!(
            instruction.0.opcode,
            Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU
                | Opcode::JAL
                | Opcode::JALR
        )
    }
}
