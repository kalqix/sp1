use std::sync::Arc;

use hashbrown::HashMap;
use sp1_hypercube::air::PROOF_NONCE_NUM_WORDS;
use sp1_jit::MinimalTrace;

use crate::{
    CoreVM, CycleResult, ExecutionError, MinimalExecutor, Opcode, Program, SP1Context, SP1CoreOpts,
};

/// Execute a program and count how many times each program counter is visited.
pub fn execute_for_frequency_map<'a>(
    program: &Arc<Program>,
    input: impl Iterator<Item = &'a [u8]>,
) -> Result<HashMap<u64, u32>, ExecutionError> {
    let opts = SP1CoreOpts::default();
    let proof_nonce = SP1Context::default().proof_nonce;

    let mut minimal_executor =
        MinimalExecutor::tracing(program.clone(), opts.minimal_trace_chunk_threshold);

    for buf in input {
        minimal_executor.with_input(buf);
    }

    let mut pc_counts = HashMap::new();
    while let Some(chunk) = minimal_executor.execute_chunk() {
        let mut vm = FrequencyMapVM::new(&chunk, program.clone(), opts.clone(), proof_nonce);

        loop {
            match vm.execute_instruction(&mut pc_counts)? {
                CycleResult::Done(false) => {}
                CycleResult::TraceEnd => break,
                CycleResult::Done(true) => return Ok(pc_counts),
                CycleResult::ShardBoundary => {
                    unreachable!("Shard boundaries are not expected in pure execution")
                }
            }
        }
    }

    Ok(pc_counts)
}

struct FrequencyMapVM<'a> {
    core: CoreVM<'a, ()>,
}

impl<'a> FrequencyMapVM<'a> {
    fn new<T: MinimalTrace>(
        trace: &'a T,
        program: Arc<Program>,
        opts: SP1CoreOpts,
        proof_nonce: [u32; PROOF_NONCE_NUM_WORDS],
    ) -> Self {
        Self { core: CoreVM::new(trace, program, opts, proof_nonce) }
    }

    fn execute_instruction(
        &mut self,
        pc_counts: &mut HashMap<u64, u32>,
    ) -> Result<CycleResult, ExecutionError> {
        let pc = self.core.pc();
        *pc_counts.entry(pc).or_insert(0) += 1;

        let instruction = self.core.fetch(|| ());
        if instruction.is_none() {
            unreachable!("Fetching the next instruction failed");
        }

        // SAFETY: The instruction is guaranteed to be valid as we checked for `is_none` above.
        let instruction = unsafe { instruction.unwrap_unchecked() };
        let instruction = *instruction;

        match instruction.opcode {
            Opcode::ADD
            | Opcode::ADDI
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SLLW
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::MUL
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::MULH
            | Opcode::MULW
            | Opcode::DIVU
            | Opcode::REMU
            | Opcode::DIV
            | Opcode::REM
            | Opcode::DIVW
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::DIVUW
            | Opcode::REMUW
            | Opcode::REMW => {
                let _ = self.core.execute_alu(&instruction);
            }
            Opcode::LB
            | Opcode::LBU
            | Opcode::LH
            | Opcode::LHU
            | Opcode::LW
            | Opcode::LWU
            | Opcode::LD => {
                let _ = self.core.execute_load(&instruction)?;
            }
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                let _ = self.core.execute_store(&instruction)?;
            }
            Opcode::JAL | Opcode::JALR => {
                let _ = self.core.execute_jump(&instruction);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                let _ = self.core.execute_branch(&instruction);
            }
            Opcode::LUI | Opcode::AUIPC => {
                let _ = self.core.execute_utype(&instruction);
            }
            Opcode::ECALL => {
                let code = self.core.read_code();
                let _ = CoreVM::<()>::execute_ecall(&mut self.core, &instruction, code)?;
            }
            Opcode::EBREAK | Opcode::UNIMP => {
                unreachable!("Invalid opcode for `execute_instruction`: {:?}", instruction.opcode)
            }
        }

        let (res, calls) = self.core.advance(|| ());
        assert!(
            calls.is_empty(),
            "Frequency map collection should happen on the program with no apcs, but we found apc calls"
        );

        Ok(res)
    }
}
