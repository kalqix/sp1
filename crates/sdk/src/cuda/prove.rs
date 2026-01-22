// //! # CUDA Proving
// //!
// //! This module provides a builder for proving a program on the CUDA.

use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

use sp1_cuda::CudaClientError;

use super::CudaProver;
use crate::{
    prover::{BaseProveRequest, ProveRequest},
    utils::proof_mode,
    SP1ProofWithPublicValues,
};
use sp1_primitives::SP1GlobalContext;
use sp1_prover::{CoreAirProverFactory, SP1ProverComponents};

/// A builder for proving a program on the CUDA.
///
/// This builder provides a typed interface for configuring the SP1 RISC-V prover. The builder is
/// used for only the [`crate::cuda::CudaProver`] client type.
pub struct CudaProveRequest<'a, C>
where
    C: SP1ProverComponents,
    C::CoreProver: CoreAirProverFactory<SP1GlobalContext, C::CoreSC>,
{
    pub(crate) base: BaseProveRequest<'a, CudaProver<C>>,
}

impl<'a, C> ProveRequest<'a, CudaProver<C>> for CudaProveRequest<'a, C>
where
    C: SP1ProverComponents,
    C::CoreProver: CoreAirProverFactory<SP1GlobalContext, C::CoreSC>,
{
    fn base(&mut self) -> &mut BaseProveRequest<'a, CudaProver<C>> {
        &mut self.base
    }
}

impl<'a, C> IntoFuture for CudaProveRequest<'a, C>
where
    C: SP1ProverComponents,
    C::CoreProver: CoreAirProverFactory<SP1GlobalContext, C::CoreSC>,
{
    type Output = Result<SP1ProofWithPublicValues, CudaClientError>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let BaseProveRequest { prover, pk, stdin, mode, mut context_builder } = self.base;

        let context = context_builder.build();
        Box::pin(async move {
            Ok(prover.prover.prove_with_mode(pk, stdin, context, proof_mode(mode)).await?.into())
        })
    }
}
