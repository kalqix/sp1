//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use std::sync::Arc;

use super::CudaProver;
use crate::cpu::CpuProver;
use powdr_autoprecompiles::Apc;
use slop_baby_bear::BabyBear;
use sp1_core_machine::autoprecompiles::instruction::Sp1Instruction;
use sp1_cuda::CudaProver as CudaProverImpl;

/// A builder for the [`CudaProver`].
///
/// The builder is used to configure the [`CudaProver`] before it is built.
#[derive(Debug, Default)]
pub struct CudaProverBuilder {
    cuda_device_id: Option<u32>,
    apcs: Vec<Arc<Apc<BabyBear, Sp1Instruction>>>,
}

impl CudaProverBuilder {
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

    /// Adds any autoprecompiles (APCs) that should be supported by the prover.
    #[must_use]
    pub fn with_apcs(mut self, apcs: Vec<Arc<Apc<BabyBear, Sp1Instruction>>>) -> Self {
        self.apcs = apcs;
        self
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
    pub async fn build(self) -> CudaProver {
        let cpu_prover = CpuProver::new(self.apcs).await;
        let cuda_prover = match self.cuda_device_id {
            Some(id) => CudaProverImpl::new_with_id(id).await,
            None => CudaProverImpl::new().await,
        };

        CudaProver {
            cpu_prover,
            prover: cuda_prover.expect("Failed to create the CUDA prover impl"),
        }
    }
}
