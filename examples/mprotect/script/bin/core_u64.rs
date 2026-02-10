use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;


/// The ELF we want to execute inside the zkVM.
const ELF: Elf = include_elf!("mprotect-program");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::default();
    // Set the flags to true to test the failure cases.
    let execute_prot_should_fail = false;
    let test_prot_none_fail = false;

    stdin.write(&execute_prot_should_fail);
    stdin.write(&test_prot_none_fail);

<<<<<<< HEAD
    let sp1_prover = SP1ProverBuilder::<CpuSP1ProverComponents>::new(RiscvAirWithApcs::machine()).build().await;
    let opts = LocalProverOpts {
        core_opts: SP1CoreOpts {
            retained_events_presets: [RetainedEventsPreset::Sha256].into(),
            // page_protect: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let prover = Arc::new(LocalProver::new(sp1_prover, opts));

    let (pk, program, vk) = prover
        .prover()
        .core()
        .setup(&*ELF)
        .instrument(tracing::debug_span!("setup").or_current())
        .await;

    let pk = unsafe { pk.into_inner() };

    let core_proof = prover
        .clone()
        .prove_core(pk, program, stdin, SP1Context::default())
        .instrument(tracing::info_span!("prove core"))
        .await
        .unwrap();

    // Verify the proof
    let core_proof_data = SP1CoreProofData(core_proof.proof.0.clone());
    prover.prover().verify(&core_proof_data, &vk).unwrap();
=======
    let client = ProverClient::from_env(RiscvAirWithApcs::machine()).await;
    let pk = client.setup(ELF).await.unwrap();
    let proof = client.prove(&pk, stdin).core().await.unwrap();
    client.verify(&proof, &pk.verifying_key(), None).unwrap();
>>>>>>> a32b4d66845a78fce3fac3dbbbdb4a9fe552a938
}
