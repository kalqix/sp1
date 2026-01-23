use slop_algebra::extension::BinomialExtensionField;
use slop_challenger::IopCtx;
use slop_jagged::{DefaultJaggedProver, JaggedProver};
use slop_multilinear::{MultilinearPcsProver, MultilinearPcsVerifier};
use slop_stacked::StackedPcsProver;
use sp1_primitives::{SP1Field, SP1GlobalContext};

use super::{DefaultTraceGenerator, ShardProver, SimpleProver, ZerocheckAir};
use crate::{
    prover::{PcsProof, SP1MerkleTreeProver},
    GkrProverImpl, InnerSC, LogupGkrCpuTraceGenerator, SP1Pcs, ShardContext, ShardContextImpl,
    ShardVerifier,
};

type SC<GC, Verifier, A> = ShardContextImpl<GC, Verifier, A>;

/// A CPU shard prover.
pub type CpuShardProver<GC, Verifier, PcsComponents, A> =
    ShardProver<GC, SC<GC, Verifier, A>, PcsComponents>;

/// A CPU simple prover.
pub type CpuSimpleProver<GC, Verifier, PcsComponents, A> =
    SimpleProver<GC, SC<GC, Verifier, A>, CpuShardProver<GC, Verifier, PcsComponents, A>>;

impl<GC, SC, C> ShardProver<GC, SC, C>
where
    GC: IopCtx,
    SC: ShardContext<GC>,
    SC::Config: MultilinearPcsVerifier<GC>,
    C: MultilinearPcsProver<GC, PcsProof<GC, SC>> + DefaultJaggedProver<GC, SC::Config>,
{
    /// Create a new CPU prover.
    #[must_use]
    pub fn new(verifier: ShardVerifier<GC, SC>) -> Self {
        // Construct the shard prover.
        let ShardVerifier { jagged_pcs_verifier: pcs_verifier, machine } = verifier;
        let pcs_prover = JaggedProver::from_verifier(&pcs_verifier);
        let trace_generator = DefaultTraceGenerator::new(machine);
        let logup_gkr_trace_generator = LogupGkrCpuTraceGenerator::default();
        let logup_gkr_prover = GkrProverImpl::new(logup_gkr_trace_generator);

        Self { trace_generator, logup_gkr_prover, pcs_prover }
    }
}

/// Create a [`SimpleProver`] from a verifier with a single permit.
///
/// This is the recommended way to create a prover for tests and development.
#[must_use]
pub fn simple_prover<A>(
    verifier: ShardVerifier<SP1GlobalContext, InnerSC<A>>,
) -> CpuSimpleProver<
    SP1GlobalContext,
    SP1Pcs<SP1GlobalContext>,
    StackedPcsProver<SP1MerkleTreeProver, SP1GlobalContext>,
    A,
>
where
    A: ZerocheckAir<SP1Field, BinomialExtensionField<SP1Field, 4>>,
{
    let shard_prover = CpuShardProver::new(verifier.clone());
    SimpleProver::new(verifier, shard_prover)
}
