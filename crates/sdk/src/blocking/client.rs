//! # SP1 Prover Client
//!
//! A client for interacting with the prover for the SP1 RISC-V zkVM.

use std::marker::PhantomData;

use crate::blocking::{
    cpu::builder::CpuProverBuilder, cuda::builder::CudaProverBuilder, env::EnvProver,
};
use derive_where::derive_where;
use sp1_hypercube::{Machine, ShardContext};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover::SP1ProverComponents;

/// An entrypoint for interacting with the prover for the SP1 RISC-V zkVM.
///
/// IMPORTANT: `ProverClient` only needs to be initialized ONCE and can be reused for subsequent
/// proving operations, all provers types are cheap to clone and share across threads.
///
/// Note that the initialization may be slow as it loads necessary proving parameters and sets up
/// the environment.
#[derive_where(Default)]
pub struct ProverClient<C> {
    _marker: PhantomData<C>,
}

impl<C: SP1ProverComponents> ProverClient<C> {
    /// Builds an [`EnvProver`], which loads the mode and any settings from the environment.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// std::env::set_var("SP1_PROVER", "cuda");
    /// let prover = ProverClient::from_env();
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    pub fn from_env(
        machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> EnvProver<C> {
        EnvProver::new(machine)
    }

    /// Creates a new [`ProverClientBuilder`] so that you can configure the prover client.
    #[must_use]
    pub fn builder() -> ProverClientBuilder<C> {
        ProverClientBuilder::default()
    }
}

/// A builder to define which proving client to use.
#[derive_where(Default)]
pub struct ProverClientBuilder<C> {
    _marker: PhantomData<C>,
}

impl<C: SP1ProverComponents> ProverClientBuilder<C> {
    /// Builds a [`CpuProver`] specifically for local CPU proving.
    ///
    /// # Usage
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cpu().build();
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn cpu(&self) -> CpuProverBuilder<C> {
        CpuProverBuilder::new()
    }

    /// Builds a [`CudaProver`] specifically for local proving on NVIDIA GPUs.
    ///
    /// # Example
    /// ```no_run
    /// use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
    ///
    /// let elf = Elf::Static(&[1, 2, 3]);
    /// let stdin = SP1Stdin::new();
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// let pk = prover.setup(elf).unwrap();
    /// let proof = prover.prove(&pk, stdin).compressed().run().unwrap();
    /// ```
    #[must_use]
    #[allow(clippy::unused_self)]
    pub fn cuda(&self) -> CudaProverBuilder<C> {
        CudaProverBuilder::new()
    }
}
