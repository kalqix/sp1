//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use std::marker::PhantomData;

use sp1_hypercube::{Machine, ShardContext};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover::SP1ProverComponents;

use crate::{cpu::builder::CpuProverBuilder, cuda::builder::CudaProverBuilder, env::EnvProver};

#[cfg(feature = "network")]
use crate::network::{builder::NetworkProverBuilder, NetworkMode};

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
///
/// IMPORTANT: `ProverClient` only needs to be initialized ONCE and can be reused for subsequent
/// proving operations, all provers types are cheap to clone and share across threads.
///
/// Note that the initialization may be slow as it loads necessary proving parameters and sets up
/// the environment.
pub struct ProverClient<C> {
    _marker: PhantomData<C>,
}

impl<C: SP1ProverComponents> ProverClient<C> {
    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     std::env::set_var("SP1_PROVER", "network");
    ///     std::env::set_var("NETWORK_PRIVATE_KEY", "...");
    ///     let prover = ProverClient::from_env().await;
    ///
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub async fn from_env(
        machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> EnvProver<C> {
        EnvProver::new(machine).await
    }

    /// Creates a new [`ProverClientBuilder`] so that you can configure the prover client.
    #[must_use]
    pub fn builder(
        machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> ProverClientBuilder<C> {
        ProverClientBuilder::new(machine)
    }
}

/// A builder to define which proving client to use.
pub struct ProverClientBuilder<C: SP1ProverComponents> {
    machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
}

impl<C: SP1ProverComponents> ProverClientBuilder<C> {
    fn new(machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>) -> Self {
        Self { machine }
    }

    /// Builds a [`CpuProver`] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().cpu().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn cpu(&self) -> CpuProverBuilder<C> {
        CpuProverBuilder::default()
    }

    /// Builds a [`CudaProver`] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().cuda().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn cuda(&self) -> CudaProverBuilder<C> {
        CudaProverBuilder::default()
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().network().build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network(&self) -> NetworkProverBuilder<C> {
        NetworkProverBuilder::new(self.machine.clone())
    }

    /// Builds a [`NetworkProver`] specifically for proving on the network with a specified mode.
    ///
    /// # Examples
    /// ```no_run
    /// use sp1_sdk::{network::NetworkMode, Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// tokio_test::block_on(async {
    ///     let elf = Elf::Static(&[1, 2, 3]);
    ///     let stdin = SP1Stdin::new();
    ///
    ///     let prover = ProverClient::builder().network_for(NetworkMode::Mainnet).build().await;
    ///     let pk = prover.setup(elf).await.unwrap();
    ///     let proof = prover.prove(&pk, stdin).compressed().await.unwrap();
    /// });
    /// ```
    #[cfg(feature = "network")]
    #[must_use]
    pub fn network_for(&self, mode: NetworkMode) -> NetworkProverBuilder<C> {
        NetworkProverBuilder {
            private_key: None,
            signer: None,
            rpc_url: None,
            tee_signers: None,
            network_mode: Some(mode),
            machine: self.machine.clone(),
        }
    }
}
