use crate::{
    autoprecompiles::{
        adapter::Sp1ApcAdapter, build_elf, compile_guest, execution_profile_from_guest,
        execution_profile_from_program, instruction::Sp1Instruction,
        instruction_handler::Sp1InstructionHandler, program::Sp1Program, sp1_powdr_config,
    },
    io::SP1Stdin,
    utils::setup_logger,
};
use powdr_autoprecompiles::{
    blocks::{collect_basic_blocks, Program as PowdrProgram},
    evaluation::AirStats,
    InstructionHandler, PgoConfig,
};
use rand::{distributions::Distribution, rngs::StdRng, Rng, SeedableRng};
use sp1_core_executor::{Program, SP1CoreOpts};

const GUEST_FIBONACCI: &str = "../../test-artifacts/programs/fibonacci";
const GUEST_KECCAK256_SOFTWARE: &str = "../../test-artifacts/programs/keccak256-software";
const GUEST_KECCAK256_SOFTWARE_NUM_CASES: usize = 10000; // Number of Keccak hashes to compute
const GUEST_KECCAK256_SOFTWARE_CASE_MAX_LEN: usize = 10; // Max number of bytes in each hash input

const APC: u64 = 10;
const APC_SKIP: u64 = 0;

fn test_execution_profile(guest_path: &str, stdin: Option<SP1Stdin>) {
    setup_logger();

    let elf = build_elf(guest_path);
    let sp1_opts = SP1CoreOpts::default();

    let program = Program::from(&elf).unwrap();
    let sp1_program = Sp1Program::from(program.clone());

    let execution_profile = execution_profile_from_program(program, sp1_opts, stdin);

    // Check that all executed pc are within the program's range
    let pc_min = execution_profile.keys().min().unwrap();
    let pc_max = execution_profile.keys().max().unwrap();
    assert!(*pc_min >= sp1_program.base_pc());
    assert!(
        *pc_max
            <= sp1_program.base_pc() + sp1_program.length() as u64 * sp1_program.pc_step() as u64
    );
}

fn seeded_random_preimages_with_bounded_len(count: usize, len: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed);

    (0..count)
        .map(|_| {
            let actual_len = rand::distributions::Uniform::new(0_usize, len).sample(&mut rng);
            (0..actual_len).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>()
        })
        .collect()
}

fn keccak256_software_stdin() -> SP1Stdin {
    let mut stdin = SP1Stdin::default();
    let preimages = seeded_random_preimages_with_bounded_len(
        GUEST_KECCAK256_SOFTWARE_NUM_CASES,
        GUEST_KECCAK256_SOFTWARE_CASE_MAX_LEN,
        1234, // randomness seed
    );
    let inputs_len = preimages.len();
    stdin.write(&inputs_len);
    for preimage in preimages {
        stdin.write(&preimage);
    }
    stdin
}

#[test]
fn test_execution_profile_keccak256_software() {
    test_execution_profile(GUEST_KECCAK256_SOFTWARE, Some(keccak256_software_stdin()));
}

#[test]
fn test_execution_profile_fibonacci() {
    test_execution_profile(GUEST_FIBONACCI, None);
}

#[test]
fn test_compile_program_keccak256_software() {
    setup_logger();
    let config = sp1_powdr_config(APC, APC_SKIP);
    let pgo_config = PgoConfig::None;
    let _ = compile_guest(GUEST_KECCAK256_SOFTWARE, config, pgo_config);
}

#[test]
fn test_compile_program_keccak256_software_cell_pgo() {
    setup_logger();

    let execution_profile = execution_profile_from_guest(
        GUEST_KECCAK256_SOFTWARE,
        SP1CoreOpts::default(),
        Some(keccak256_software_stdin()),
    );

    let path = std::path::Path::new("apc_candidates");
    let config = sp1_powdr_config(APC, APC_SKIP).with_apc_candidates_dir(path);
    // Cell pgo that only creates APCs for basic blocks with fewer than 1000 instructions
    let pgo_config = PgoConfig::Cell(execution_profile, None, Some(1000));
    let compiled_program = compile_guest(GUEST_KECCAK256_SOFTWARE, config, pgo_config);

    let (apc_stats_before, apc_stats_after): (Vec<AirStats>, Vec<AirStats>) = compiled_program
        .apcs_and_stats
        .into_iter()
        .map(|(_, s)| (s.as_ref().unwrap().before, s.as_ref().unwrap().after))
        .unzip();

    // Currently just sum up the before and after stats for each APC, but APC-level analysis is also
    // available.
    let apc_stats_before = apc_stats_before.into_iter().sum::<AirStats>();
    let apc_stats_after = apc_stats_after.into_iter().sum::<AirStats>();

    assert_eq!(
        apc_stats_before,
        AirStats { main_columns: 1107, constraints: 787, bus_interactions: 515 }
    );
    assert_eq!(
        apc_stats_after,
        AirStats { main_columns: 256, constraints: 61, bus_interactions: 245 }
    );
}

#[test]
fn test_compile_program_fibonacci() {
    setup_logger();

    let config = sp1_powdr_config(APC, APC_SKIP);
    let pgo_config = PgoConfig::None;
    let _ = compile_guest(GUEST_FIBONACCI, config, pgo_config);
}

#[test]
fn test_collect_basic_blocks_keccak256_software() {
    setup_logger();

    test_collect_basic_blocks(GUEST_KECCAK256_SOFTWARE, 1870);
}

#[test]
fn test_collect_basic_blocks_fibonacci() {
    setup_logger();

    test_collect_basic_blocks(GUEST_FIBONACCI, 1628);
}

fn test_collect_basic_blocks(guest_path: &str, expected_bb_len: usize) {
    let elf = build_elf(guest_path);

    let sp1_program = Sp1Program::from(Program::from(&elf).unwrap());
    let jumpdest_set = powdr_riscv_elf::rv64::compute_jumpdests_from_buffer(&elf).jumpdests;
    let instruction_handler = Sp1InstructionHandler::<slop_baby_bear::BabyBear>::new();

    // Check total number of basic blocks produced
    let basic_blocks =
        collect_basic_blocks::<Sp1ApcAdapter>(&sp1_program, &jumpdest_set, &instruction_handler);
    let basic_blocks_length = basic_blocks.len();
    assert_eq!(basic_blocks_length, expected_bb_len);

    // Check the validity of each basic block
    basic_blocks.iter().enumerate().fold(None::<Sp1Instruction>, |prior, (idx, bb)| {
        // Every block must be non-empty
        assert!(!bb.statements.is_empty(), "Basic block must not be empty");

        // A basic block must:
        // start with a not allowed instruction (in which case it's alone in its own block)
        // OR start with a target instruction
        // OR the last instruction of the prior block is branching/not allowed instruction
        // OR is the first block
        let first = &bb.statements[0];
        if !instruction_handler.is_allowed(first) {
            assert!(
                bb.statements.len() == 1,
                "Block with not allowed instruction must be in its own block"
            );
        } else if idx != 0 {
            let prev = prior.as_ref().expect("Prior should be set after the first iteration");
            assert!(
                instruction_handler.is_branching(prev)
                    || jumpdest_set.contains(&bb.start_pc)
                    || !instruction_handler.is_allowed(prev),
                "Block must start at a jumpdest or after a branching instruction"
            );
        }

        // Update the last instruction of the prior block for the next iteration
        Some(bb.statements.last().unwrap().clone())
    });
}
