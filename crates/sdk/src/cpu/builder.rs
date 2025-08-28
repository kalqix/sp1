//! # CPU Prover Builder
//!
//! This module provides a builder for the [`CpuProver`].

use std::sync::Arc;

use powdr_autoprecompiles::Apc;
use slop_baby_bear::BabyBear;
use sp1_core_machine::autoprecompiles::instruction::Sp1Instruction;

use super::CpuProver;

/// A builder for the [`CpuProver`].
///
/// The builder is used to configure the [`CpuProver`] before it is built.
#[derive(Default)]
pub struct CpuProverBuilder {
    apcs: Vec<Arc<Apc<BabyBear, Sp1Instruction>>>,
}

impl CpuProverBuilder {
    /// Adds any autoprecompiles (APCs) that should be supported by the prover.
    #[must_use]
    pub fn with_apcs(mut self, apcs: Vec<Arc<Apc<BabyBear, Sp1Instruction>>>) -> Self {
        self.apcs = apcs;
        self
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
    /// let prover = ProverClient::builder().mock().build();
    /// ```
    #[must_use]
    pub async fn build(self) -> CpuProver {
        CpuProver::new(self.apcs).await
    }
}
