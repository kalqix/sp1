//! # SP1 CUDA Prover
//!
//! A prover that uses the CUDA to execute and prove programs.

/// The builder for the CUDA prover.
pub mod builder;
/// The CUDA prove request type.
pub mod prove;

use crate::{
    prover::{BaseProveRequest, Prover, SendFutureResult},
    ProvingKey,
};

use prove::CudaProveRequest;
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_cuda::{CudaClientError, CudaProver as CudaProverImpl, CudaProvingKey};
use sp1_primitives::Elf;
use sp1_prover::{
    worker::{SP1LightNode, SP1NodeCore},
    SP1VerifyingKey,
};

/// A prover that uses the CPU for execution and the CUDA for proving.
#[derive(Clone)]
pub struct CudaProver {
    pub(crate) node: SP1LightNode,
    pub(crate) prover: CudaProverImpl,
}

impl CudaProver {
    /// Extract and serialize APCs from the node's machine.
    fn serialized_apcs(&self) -> Vec<u8> {
        let apcs: Vec<_> = self
            .node
            .inner()
            .machine()
            .chips()
            .iter()
            .filter_map(|chip| match chip.air.as_ref() {
                RiscvAir::Apc(apc_chip) => Some(apc_chip.apc().clone()),
                _ => None,
            })
            .collect();
        if apcs.is_empty() {
            vec![]
        } else {
            serde_cbor::to_vec(&apcs).unwrap()
        }
    }
}

impl Prover for CudaProver {
    type ProvingKey = CudaProvingKey;
    type Error = CudaClientError;
    type ProveRequest<'a> = CudaProveRequest<'a>;

    fn inner(&self) -> &SP1NodeCore {
        self.node.inner()
    }

    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        let prover = self.prover.clone();
        let apcs = self.serialized_apcs();
        async move { prover.setup(elf, apcs).await }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        CudaProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}

impl ProvingKey for CudaProvingKey {
    fn elf(&self) -> &Elf {
        self.elf()
    }

    fn verifying_key(&self) -> &SP1VerifyingKey {
        self.verifying_key()
    }
}
