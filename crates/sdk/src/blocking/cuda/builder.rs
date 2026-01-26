//! # CUDA Prover Builder
//!
//! This module provides a builder for the [`CudaProver`].

use super::CudaProver;
use crate::blocking::block_on;
use sp1_core_executor::SP1CoreOpts;
use sp1_core_machine::riscv::RiscvAirWithApcs;
use sp1_cuda::CudaProver as CudaProverImpl;
use sp1_hypercube::Machine;
use sp1_primitives::SP1Field;
use sp1_prover::worker::SP1LightNode;

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
#[derive(Debug)]
pub struct CudaProverBuilder {
    cuda_device_id: Option<u32>,
    /// Optional core options to configure the underlying CPU prover.
    core_opts: Option<SP1CoreOpts>,
    machine: Option<Machine<SP1Field, RiscvAirWithApcs<SP1Field>>>,
}

impl Default for CudaProverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CudaProverBuilder {
    /// Creates a new [`CpuProverBuilder`] with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self { cuda_device_id: None, core_opts: None, machine: None }
    }

    /// Sets the core machine used by the prover.
    #[must_use]
    pub fn with_machine(
        mut self,
        machine: Machine<SP1Field, RiscvAirWithApcs<SP1Field>>,
    ) -> Self {
        self.machine = Some(machine);
        self
    }

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
    /// let mut opts = SP1CoreOpts::default();
    /// opts.shard_size = 500_000;
    /// let prover = ProverClient::builder().cuda().core_opts(opts).build();
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
    /// let mut opts = SP1CoreOpts::default();
    /// opts.shard_size = 500_000;
    /// let prover = ProverClient::builder().cuda().with_opts(opts).build();
    /// ```
    #[must_use]
    pub fn with_opts(self, opts: SP1CoreOpts) -> Self {
        self.core_opts(opts)
    }

    /// Creates a builder using the provided machine.
    #[must_use]
    pub fn new_with_machine(
        machine: Machine<SP1Field, RiscvAirWithApcs<SP1Field>>,
    ) -> Self {
        Self::new().with_machine(machine)
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
    pub fn build(self) -> CudaProver {
        let node = block_on(SP1LightNode::with_opts(
            self.machine.expect("Machine should be set"),
            self.core_opts.unwrap_or_default(),
        ));
        let cuda_prover = match self.cuda_device_id {
            Some(id) => crate::blocking::block_on(CudaProverImpl::new_with_id(id)),
            None => crate::blocking::block_on(CudaProverImpl::new()),
        };

        CudaProver { node, prover: cuda_prover.expect("Failed to create the CUDA prover impl") }
    }
}
