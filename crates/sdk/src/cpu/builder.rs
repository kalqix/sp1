//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use derive_where::derive_where;
use sp1_hypercube::{Machine, ShardContext};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover::SP1ProverComponents;

use super::CpuProver;
use sp1_core_executor::SP1CoreOpts;

/// A builder for the [`CpuProver`].
///
/// The builder is used to configure the [`CpuProver`] before it is built.
#[derive_where(Default)]
pub struct CpuProverBuilder<C: SP1ProverComponents> {
    /// Optional core options to configure the prover.
    core_opts: Option<SP1CoreOpts>,
    machine: Option<Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: SP1ProverComponents> CpuProverBuilder<C> {
    /// Creates a new [`CpuProverBuilder`] with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { core_opts: None, machine: None, _marker: std::marker::PhantomData }
    }

    /// Sets the core machine used by the prover.
    #[must_use]
    pub fn with_machine(
        mut self,
        machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> Self {
        self.machine = Some(machine);
        self
    }

    /// Creates a builder using the provided machine.
    #[must_use]
    pub fn new_with_machine(
        machine: Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> Self {
        Self::new().with_machine(machine)
    }

    /// Sets the core options for the prover.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cpu().core_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the prover (alias for `core_opts`).
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cpu().with_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Builds a [`CpuProver`].
    ///
    /// # Details
    /// This method will build a [`CpuProver`] with the given parameters. In particular, it will
    /// build a mock prover if the `mock` flag is set.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let prover = ProverClient::builder().cpu().build().await;
    /// });
    /// ```
    #[must_use]
    pub async fn build(self) -> CpuProver<C> {
        let machine = self.machine.expect("CpuProverBuilder requires a machine");
        CpuProver::new(machine).await
    }
}
