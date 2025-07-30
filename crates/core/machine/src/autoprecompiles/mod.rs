pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod instruction;
pub mod instruction_handler;
pub mod interaction_builder;
pub mod memory_bus_interaction;
pub mod program;
#[cfg(test)]
mod tests;

use powdr_autoprecompiles::{
    adapter::AdapterApc,
    blocks::{collect_basic_blocks, generate_apcs_with_pgo},
    execution_profile::execution_profile,
    DegreeBound, PgoConfig, PowdrConfig,
};
use slop_baby_bear::BabyBear;
use sp1_build::{BuildArgs, DEFAULT_TARGET_64};
use sp1_core_executor::{Executor, Program, SP1CoreOpts};
use std::{collections::HashMap, sync::Arc};

use crate::{
    autoprecompiles::{
        adapter::Sp1ApcAdapter,
        bus_interaction_handler::Sp1BusInteractionHandler,
        bus_map::{sp1_bus_map, Sp1SpecificBuses},
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

    let program = Program::from(&elf).unwrap();

    execution_profile_from_program(program, sp1_opts, stdin)
}

pub fn execution_profile_from_program(
    program: Program,
    sp1_opts: SP1CoreOpts,
    stdin: Option<SP1Stdin>,
) -> HashMap<u64, u32> {
    let mut executor = Executor::new(Arc::new(program.clone()), sp1_opts);
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

pub struct CompiledProgram {
    pub apcs: Vec<AdapterApc<Sp1ApcAdapter>>,
}

impl CompiledProgram {
    pub fn new(elf: &[u8], config: PowdrConfig, pgo_config: PgoConfig) -> Self {
        let program = Sp1Program::from(Program::from(elf).unwrap());
        let jumpdests = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(elf).jumpdests;

        let airs = Sp1InstructionHandler::<BabyBear>::new();
        let vm_config = sp1_vm_config(&airs);

        // Currently we don't support the max_total_apc_columns option for cell PGO
        assert!(!matches!(pgo_config, PgoConfig::Cell(_, Some(_), _)));

        // Collect basic blocks
        let blocks = collect_basic_blocks::<Sp1ApcAdapter>(&program, &jumpdests, &airs);
        tracing::info!("Got {} basic blocks from `collect_basic_blocks`", blocks.len());

        // Generate APC
        let apcs =
            generate_apcs_with_pgo::<Sp1ApcAdapter>(blocks, &config, None, pgo_config, vm_config);

        let apcs = apcs.into_iter().map(|(apc, _)| apc).collect::<Vec<_>>();

        Self { apcs }
    }
}
