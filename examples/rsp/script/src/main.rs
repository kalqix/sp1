// use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
use powdr_autoprecompiles::PgoConfig;
use sp1_build::include_elf;
use sp1_build::Elf;
use sp1_core_executor::Program;
use sp1_core_machine::autoprecompiles::execution_profile_from_program;
use sp1_core_machine::autoprecompiles::sp1_powdr_config;
use sp1_core_machine::autoprecompiles::CompiledProgram;
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rsp_client_executor::{io::ClientExecutorInput, CHAIN_ID_ETH_MAINNET};
use sp1_sdk::ProveRequest;
use sp1_sdk::Prover;
use sp1_sdk::ProvingKey;
use std::path::PathBuf;

/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("rsp-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute the RSP program
    Execute,
    /// Generate APCs using Powdr
    Powdr,
    /// Prove the RSP program
    Prove {
        /// Number of APCs to enable (0 = disabled)
        #[arg(long, default_value_t = 0)]
        apcs: usize,
    },
}

fn load_input_from_cache(chain_id: u64, block_number: u64) -> ClientExecutorInput {
    let cache_path = PathBuf::from(format!("./input/{}/{}.bin", chain_id, block_number));
    let mut cache_file = std::fs::File::open(cache_path).unwrap();
    let client_input: ClientExecutorInput = bincode::deserialize_from(&mut cache_file).unwrap();

    client_input
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    // Load the input from the cache.
    let block = 20526624; // ~2.4M Gas
                          // let block = 21740164; // ~15M Gas
                          // let block = 21740137; // ~29M Gas
    let client_input = load_input_from_cache(CHAIN_ID_ETH_MAINNET, block);
    let mut stdin = SP1Stdin::default();
    let buffer = bincode::serialize(&client_input).unwrap();
    stdin.write_vec(buffer);

    let program = Arc::new(Program::from(&ELF).unwrap());

    match args.command {
        Commands::Execute => {
            todo!()
        }
        Commands::Powdr => {
            println!("[powdr] Getting execution profile...");
            let execution_profile = execution_profile_from_program(program, stdin);

            println!("[powdr] Generating APCs...");
            let path = std::path::Path::new("apc_candidates");
            let config = sp1_powdr_config(1, 0).with_apc_candidates_dir(path);
            let pgo_config = PgoConfig::Cell(execution_profile, None);
            let _compiled_program = CompiledProgram::new(&ELF, config, pgo_config);

            println!("[powdr] Done!");
        }
        Commands::Prove { apcs } => {
            let apcs = if apcs > 0 {
                println!("[powdr] Getting execution profile...");
                let execution_profile = execution_profile_from_program(program, stdin.clone());

                println!("[powdr] Generating APCs...");
                let path = std::path::Path::new("apc_candidates");
                let config = sp1_powdr_config(apcs as u64, 0).with_apc_candidates_dir(path);
                let pgo_config = PgoConfig::Cell(execution_profile, None);
                let compiled_program = CompiledProgram::new(&ELF, config, pgo_config);

                println!("[powdr] Done!");

                compiled_program
                    .apcs_and_stats
                    .into_iter()
                    .map(|a| a.into_parts())
                    .map(|(apc, _, _)| apc)
                    .collect()
            } else {
                Vec::new()
            };

            let machine = RiscvAirWithApcs::machine_with_apcs(apcs);

            let client = ProverClient::from_env(machine).await;

            let pk = client.setup(ELF).await.expect("setup failed");

            println!("Starting proving...");
            let proof = client.prove(&pk, stdin).core().await.expect("proving failed");
            println!("Done proving!");

            // Verify proof.
            client.verify(&proof, pk.verifying_key(), None).expect("verification failed");
        }
    }
}
