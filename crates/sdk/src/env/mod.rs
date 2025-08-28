//! # SP1 Environment Prover
//!
//! A prover that can execute programs and generate proofs with a different implementation based on
//! the value of the `SP1_PROVER` environment variable.

use crate::{
    cuda::builder::CudaProverBuilder,
    prover::{BaseProveRequest, SendFutureResult},
    CpuProver, CudaProver, MockProver, Prover,
};

#[cfg(feature = "network")]
use crate::NetworkProver;

pub mod pk;
/// The module that defines the prove request for the [`EnvProver`].
pub mod prove;
pub use pk::EnvProvingKey;
use powdr_autoprecompiles::Apc;
use prove::EnvProveRequest;
use slop_baby_bear::BabyBear;
use sp1_core_machine::{autoprecompiles::instruction::Sp1Instruction, io::SP1Stdin};
use sp1_primitives::Elf;
use sp1_prover::{components::CpuSP1ApcProverComponents, local::LocalProver};
use std::sync::Arc;

/// A prover that can execute programs and generate proofs with a different implementation based on
/// the value of the `SP1_PROVER` environment variable.
#[derive(Clone)]
pub enum EnvProver {
    /// A mock prover that does not prove anything.
    Mock(MockProver),
    /// A CPU prover.
    Cpu(CpuProver),
    /// A CUDA prover.
    Cuda(CudaProver),
    /// A network prover.
    #[cfg(feature = "network")]
    Network(NetworkProver),
}

impl EnvProver {
    /// Creates a new [`EnvProver`] from the environment.
    ///
    /// This method will read from the `SP1_PROVER` environment variable to determine which prover
    /// to use. If the variable is not set, it will default to the CPU prover.
    ///
    /// If the prover is a network prover, the `NETWORK_PRIVATE_KEY` variable must be set.
    pub async fn new(apcs: Vec<Arc<Apc<BabyBear, Sp1Instruction>>>) -> Self {
        let prover = match std::env::var("SP1_PROVER") {
            Ok(prover) => prover,
            Err(_) => "cpu".to_string(),
        };

        if prover.as_str() != "cpu" && !apcs.is_empty() {
            unimplemented!(
                "APCs are only supported for the CPU prover. \
                Please set the SP1_PROVER environment variable to 'cpu' or remove the APCs."
            );
        }

        match prover.as_str() {
            "cpu" => Self::Cpu(CpuProver::new(apcs).await),
            "cuda" => Self::Cuda(CudaProverBuilder::default().build().await),
            "mock" => Self::Mock(MockProver::new().await),
            #[cfg(feature = "network")]
            "network" => {
                let private_key =
                    std::env::var("NETWORK_PRIVATE_KEY").ok().filter(|k| !k.is_empty()).expect(
                        "NETWORK_PRIVATE_KEY environment variable is not set. \
                Please set it to your private key or use the .private_key() method.",
                    );

                let network_builder =
                    crate::network::builder::NetworkProverBuilder::new().private_key(&private_key);

                Self::Network(network_builder.build().await)
            }
            _ => unreachable!(),
        }
    }
}

impl Prover for EnvProver {
    type Error = anyhow::Error;
    type ProvingKey = EnvProvingKey;
    type ProveRequest<'a> = prove::EnvProveRequest<'a>;

    fn inner(&self) -> Arc<LocalProver<CpuSP1ApcProverComponents>> {
        match self {
            Self::Cpu(prover) => prover.inner(),
            Self::Cuda(prover) => prover.inner(),
            Self::Mock(prover) => prover.inner(),
            #[cfg(feature = "network")]
            Self::Network(prover) => prover.inner(),
        }
    }
    fn setup(&self, elf: Elf) -> impl SendFutureResult<Self::ProvingKey, Self::Error> {
        async move {
            match self {
                Self::Cpu(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::cpu(pk))
                }
                Self::Cuda(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::cuda(pk))
                }
                Self::Mock(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::mock(pk))
                }
                #[cfg(feature = "network")]
                Self::Network(prover) => {
                    let pk = prover.setup(elf).await?;
                    Ok(EnvProvingKey::network(pk))
                }
            }
        }
    }

    fn prove<'a>(&'a self, pk: &'a Self::ProvingKey, stdin: SP1Stdin) -> Self::ProveRequest<'a> {
        EnvProveRequest { base: BaseProveRequest::new(self, pk, stdin) }
    }
}
