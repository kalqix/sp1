//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

/// The builder for the CUDA prover.
pub mod builder;
/// The CUDA prove request type.
pub mod prove;

use crate::blocking::{prover::BaseProveRequest, Prover};

use prove::CudaProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_cuda::{CudaClientError, CudaProver as CudaProverImpl, CudaProvingKey};
use sp1_primitives::Elf;
use sp1_prover::worker::{SP1LightNode, SP1NodeCore};
use sp1_prover::SP1ProverComponents;

/// A prover that uses the CPU for execution and the CUDA for proving.
#[derive(Clone)]
pub struct CudaProver<C: SP1ProverComponents> {
    pub(crate) node: SP1LightNode<C>,
    pub(crate) prover: CudaProverImpl,
}

impl<C: SP1ProverComponents> Prover for CudaProver<C> {
    type Components = C;
    type ProvingKey = CudaProvingKey;
    type Error = CudaClientError;
    type ProveRequest<'a> = CudaProveRequest<'a, C>;

    fn inner(&self) -> &SP1NodeCore<C> {
        self.node.inner()
    }

    fn setup(&self, elf: Elf) -> Result<Self::ProvingKey, Self::Error> {
        crate::blocking::block_on(self.prover.setup(elf))
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CudaProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}
