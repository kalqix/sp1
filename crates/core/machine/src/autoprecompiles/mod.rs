pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod chip;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod memory_bus_interaction;
pub mod program;
#[cfg(test)]
mod tests;

use powdr_autoprecompiles::{
    adapter::{AdapterApc, PgoAdapter},
    blocks::{collect_basic_blocks, BasicBlock, Program as _},
    evaluation::EvaluationResult,
    execution_profile::execution_profile,
    pgo::{CellPgo, InstructionPgo, NonePgo},
    DegreeBound, PgoConfig, PowdrConfig,
};
use serde::{Deserialize, Serialize};
use slop_baby_bear::BabyBear;
use sp1_build::{BuildArgs, DEFAULT_TARGET_64};
use sp1_core_executor::{ApcRange, Executor, Program, SP1CoreOpts};
use std::{collections::HashMap, sync::Arc};

use crate::{
    autoprecompiles::{
        adapter::Sp1ApcAdapter,
        bus_interaction_handler::Sp1BusInteractionHandler,
        bus_map::{sp1_bus_map, Sp1SpecificBuses},
        candidate::Sp1Candidate,
        instruction::Sp1Instruction,
        instruction_handler::Sp1InstructionHandler,
        program::Sp1Program,
    },
    io::SP1Stdin,
};

const SP1_DEGREE_BOUND: usize = 3;
const DEFAULT_DEGREE_BOUND: DegreeBound =
    DegreeBound { identities: SP1_DEGREE_BOUND, bus_interactions: 1 };

pub type VmConfig<'a> = powdr_autoprecompiles::VmConfig<
    'a,
    Sp1InstructionHandler<BabyBear>,
    Sp1BusInteractionHandler,
    Sp1SpecificBuses,
>;

pub fn sp1_powdr_config(apc: u64, skip: u64) -> PowdrConfig {
    PowdrConfig::new(apc, skip, DEFAULT_DEGREE_BOUND)
}

pub fn sp1_vm_config<'a>(handler: &'a Sp1InstructionHandler<BabyBear>) -> VmConfig<'a> {
    // Need to pass in a handler due to VmConfig lifetime OR return a static lifetime VmConfig
    VmConfig {
        instruction_handler: handler,
        bus_interaction_handler: Sp1BusInteractionHandler::default(),
        bus_map: sp1_bus_map(),
    }
}

pub fn build_elf(guest_path: &str) -> Vec<u8> {
    let build_args = powdr_default_build_args();
    let elf_path = build_elf_path(guest_path, build_args);
    std::fs::read(elf_path).unwrap()
}

pub fn build_elf_path(guest_path: &str, build_args: BuildArgs) -> String {
    let guest_path = std::path::Path::new(guest_path).to_path_buf();
    // Currently we only take the first elf path built from the given `guest_path`, assuming that
    // there's only one binary in `guest_path` TODO: add a filter input argument and assert only
    // one elf is left after filtering
    let elf_path =
        sp1_build::execute_build_program(&build_args, Some(guest_path)).unwrap()[0].1.clone();
    elf_path.to_string()
}

pub fn compile_guest(
    guest_path: &str,
    config: PowdrConfig,
    pgo_config: PgoConfig,
) -> CompiledProgram {
    let elf = build_elf(guest_path);
    CompiledProgram::new(&elf, config, pgo_config)
}

pub fn execution_profile_from_guest(
    guest_path: &str,
    sp1_opts: SP1CoreOpts,
    stdin: Option<SP1Stdin>,
) -> HashMap<u64, u32> {
    let elf = build_elf(guest_path);

    let program = Arc::new(Program::from(&elf).unwrap());

    execution_profile_from_program(program, sp1_opts, stdin)
}

pub fn execution_profile_from_program(
    program: Arc<Program>,
    sp1_opts: SP1CoreOpts,
    stdin: Option<SP1Stdin>,
) -> HashMap<u64, u32> {
    let mut executor = Executor::new(program.clone(), sp1_opts);
    if let Some(input) = stdin {
        executor.write_vecs(&input.buffer)
    }

    execution_profile::<Sp1ApcAdapter>(&Sp1Program::from(program), || {
        executor.run_fast().unwrap();
    })
}

pub fn powdr_default_build_args() -> BuildArgs {
    BuildArgs { build_target: DEFAULT_TARGET_64.to_string(), ..Default::default() }
}

#[derive(Serialize, Deserialize)]
pub struct CompiledProgram {
    pub apcs_and_stats: Vec<(AdapterApc<Sp1ApcAdapter>, Option<EvaluationResult>)>,
}

impl CompiledProgram {
    pub fn new(elf: &[u8], config: PowdrConfig, pgo_config: PgoConfig) -> Self {
        let program = Sp1Program::from(Arc::new(Program::from(elf).unwrap()));
        let jumpdests = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf).jumpdests;

        let airs = Sp1InstructionHandler::<BabyBear>::new();
        let vm_config = sp1_vm_config(&airs);

        // Currently we don't support the max_total_apc_columns option for cell PGO
        assert!(!matches!(pgo_config, PgoConfig::Cell(_, Some(_))));

        // Collect basic blocks
        let blocks = collect_basic_blocks::<Sp1ApcAdapter>(&program, &jumpdests, &airs);
        tracing::info!("Got {} basic blocks from `collect_basic_blocks`", blocks.len());

        // Create pgo adapter based on the config
        let pgo_adapter: Box<dyn PgoAdapter<Adapter = Sp1ApcAdapter>> = match pgo_config {
            PgoConfig::Cell(pgo_data, max_total_apc_columns) => {
                Box::new(CellPgo::<_, Sp1Candidate<_>>::with_pgo_data_and_max_columns(
                    pgo_data,
                    max_total_apc_columns,
                ))
            }
            PgoConfig::Instruction(pgo_data) => Box::new(InstructionPgo::with_pgo_data(pgo_data)),
            PgoConfig::None => Box::new(NonePgo::default()),
        };

        // Generate APC
        let apcs_and_stats =
            pgo_adapter.filter_blocks_and_create_apcs_with_pgo(blocks, &config, vm_config);

        // TODO: remove this once `ApcWithStats` implements serde
        let apcs_and_stats = apcs_and_stats
            .into_iter()
            .map(|apc_with_stats| {
                let (apc, stats) = apc_with_stats.into_parts();
                (apc, stats)
            })
            .collect();

        Self { apcs_and_stats }
    }
}

/// Create APCs from the given program and ranges.
pub fn create_apcs(
    program: &Program,
    pc_idx_ranges: &[(usize, usize)],
) -> Vec<Arc<AdapterApc<Sp1ApcAdapter>>> {
    let apc_ranges: Vec<ApcRange> = pc_idx_ranges.iter().map(ApcRange::from).collect::<Vec<_>>();

    apc_ranges
        .iter()
        .map(|range| {
            let instructions = program
                .instructions
                .get_proving_range(*range)
                .iter()
                .cloned()
                .map(Sp1Instruction::from)
                .collect();

            // TODO: turn `pc_step` into a constant in the `Program` trait
            let pc_step = Sp1Program::default().pc_step() as u64;
            let start_pc = (range.start().unwrap() as u64) * pc_step + program.pc_base;

            // Create a dummy basic block with the original instructions
            let block = BasicBlock { start_pc, statements: instructions };

            // Build the APC from the block
            powdr_autoprecompiles::build::<Sp1ApcAdapter>(
                block,
                sp1_vm_config(&Sp1InstructionHandler::<BabyBear>::new()),
                DEFAULT_DEGREE_BOUND,
                None,
            )
            .expect("Failed to build APC")
        })
        .map(Arc::new)
        .collect()
}
