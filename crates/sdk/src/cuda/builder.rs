//! # CUDA Prover Builder
//!
//! This module provides a builder for the [`CudaProver`].

use std::marker::PhantomData;

use super::CudaProver;
use sp1_core_executor::SP1CoreOpts;
use sp1_cuda::CudaProver as CudaProverImpl;
use sp1_hypercube::{Machine, ShardContext};
use sp1_primitives::{SP1Field, SP1GlobalContext};
use sp1_prover::{worker::SP1LightNode, CoreAirProverFactory, SP1ProverComponents};

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
#[derive(Debug)]
pub struct CudaProverBuilder<C: SP1ProverComponents> {
    cuda_device_id: Option<u32>,
    /// Optional core options to configure the underlying CPU prover.
    core_opts: Option<SP1CoreOpts>,
    machine: Option<Machine<SP1Field, <C::CoreSC as ShardContext<SP1GlobalContext>>::Air>>,
    _marker: std::marker::PhantomData<C>,
}

impl<C: SP1ProverComponents> Default for CudaProverBuilder<C> {
    fn default() -> Self {
        Self { cuda_device_id: None, core_opts: None, machine: None, _marker: PhantomData }
    }
}

impl<C: SP1ProverComponents> CudaProverBuilder<C>
where
    C::CoreProver: CoreAirProverFactory<SP1GlobalContext, C::CoreSC>,
{
    /// Sets the CUDA device id.
    ///
    /// # Details
    /// Run the CUDA prover with the provided device id, all operations will be performed on this
    /// device index.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().with_device_id(0).build();
    /// ```
    #[must_use]
    pub fn with_device_id(mut self, id: u32) -> Self {
        self.cuda_device_id = Some(id);
        self
    }

    /// Sets the core options for the underlying CPU prover.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cuda().core_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn core_opts(mut self, opts: SP1CoreOpts) -> Self {
        self.core_opts = Some(opts);
        self
    }

    /// Sets the core options for the underlying CPU prover (alias for `core_opts`).
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_core_executor::SP1CoreOpts;
    /// use sp1_sdk::ProverClient;
    ///
    /// tokio_test::block_on(async {
    ///     let mut opts = SP1CoreOpts::default();
    ///     opts.shard_size = 500_000;
    ///     let prover = ProverClient::builder().cuda().with_opts(opts).build().await;
    /// });
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
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
        Self {
            cuda_device_id: None,
            core_opts: None,
            machine: Some(machine),
            _marker: std::marker::PhantomData,
        }
    }

    /// Builds a [`CudaProver`].
    ///
    /// # Details
    /// This method will build a [`CudaProver`] with the given parameters.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_sdk::ProverClient;
    ///
    /// let prover = ProverClient::builder().cuda().build();
    /// ```
    #[must_use]
    pub async fn build(self) -> CudaProver<C> {
        let machine = self.machine.expect("CudaProverBuilder requires a machine");
        let node = SP1LightNode::with_opts(machine, self.core_opts.unwrap_or_default()).await;
        let cuda_prover = match self.cuda_device_id {
            Some(id) => CudaProverImpl::new_with_id(id).await,
            None => CudaProverImpl::new().await,
        };

        CudaProver { node, prover: cuda_prover.expect("Failed to create the CUDA prover impl") }
    }
}
