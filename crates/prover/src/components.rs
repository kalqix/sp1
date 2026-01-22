use slop_air::Air;
use slop_challenger::IopCtx;
use slop_jagged::DefaultJaggedProver;
use slop_multilinear::MultilinearPcsProver;
use sp1_core_executor::{ExecutionRecord, Program, HEIGHT_THRESHOLD};
use sp1_core_machine::riscv::{RiscvAir, RiscvAirWithApcs};
use sp1_hypercube::{
    air::MachineAir,
    prover::{
        AirProver, CpuShardProver, PcsProof, SP1InnerPcsProver, SP1OuterPcsProver, ShardProver,
    },
    Machine, MachineVerifier, SP1InnerPcs, SP1OuterPcs, SP1Pcs, ShardContext, ShardContextImpl,
    ShardVerifier,
};
use sp1_primitives::{
    fri_params::{core_fri_config, recursion_fri_config, shrink_fri_config, wrap_fri_config},
    SP1Field, SP1GlobalContext, SP1OuterGlobalContext,
};
use sp1_recursion_circuit::zerocheck::RecursiveVerifierConstraintFolder;
use sp1_verifier::compressed::{RECURSION_LOG_STACKING_HEIGHT, RECURSION_MAX_LOG_ROW_COUNT};
use static_assertions::const_assert;

pub const CORE_LOG_STACKING_HEIGHT: u32 = 21;
pub const CORE_MAX_LOG_ROW_COUNT: usize = 22;

const_assert!(HEIGHT_THRESHOLD <= (1 << CORE_MAX_LOG_ROW_COUNT));

use sp1_recursion_machine::RecursionAir;

const COMPRESS_DEGREE: usize = 3;
const SHRINK_DEGREE: usize = 3;
const WRAP_DEGREE: usize = 3;

pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE, 2>;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE, 2>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE, 1>;

pub const RECURSION_LOG_TRACE_AREA: usize = 27;
const SHRINK_LOG_STACKING_HEIGHT: u32 = 18;
pub(crate) const SHRINK_MAX_LOG_ROW_COUNT: usize = 19;

pub(crate) const WRAP_LOG_STACKING_HEIGHT: u32 = 21;

pub type CoreSC = ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, RiscvAir<SP1Field>>;
pub type CoreSCWithApcs =
    ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, RiscvAirWithApcs<SP1Field>>;

pub type RecursionSC =
    ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, CompressAir<SP1Field>>;
pub type ShrinkSC =
    ShardContextImpl<SP1GlobalContext, SP1Pcs<SP1GlobalContext>, ShrinkAir<SP1Field>>;

pub type WrapSC =
    ShardContextImpl<SP1OuterGlobalContext, SP1Pcs<SP1OuterGlobalContext>, WrapAir<SP1Field>>;

pub trait CoreProver<SC>: AirProver<SP1GlobalContext, SC>
where
    SC: ShardContext<SP1GlobalContext, Config = SP1Pcs<SP1GlobalContext>>,
    SC::Air: MachineAir<SP1Field, Record = ExecutionRecord, Program = Program>,
{
    /// The default verifier for the core prover.
    ///
    /// The verifier fixes the parameters of the underlying proof system.
    fn verifier(machine: Machine<SP1Field, SC::Air>) -> MachineVerifier<SP1GlobalContext, SC> {
        let core_log_stacking_height = CORE_LOG_STACKING_HEIGHT;
        let core_max_log_row_count = CORE_MAX_LOG_ROW_COUNT;

        let core_verifier = ShardVerifier::from_basefold_parameters(
            core_fri_config(),
            core_log_stacking_height,
            core_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(core_verifier)
    }
}

pub trait CoreAirProverFactory<GC: IopCtx, SC: ShardContext<GC>>: AirProver<GC, SC> {
    fn from_shard_verifier(verifier: ShardVerifier<GC, SC>) -> Self;
}

impl<GC, SC, Pcs> CoreAirProverFactory<GC, SC> for ShardProver<GC, SC, Pcs>
where
    GC: IopCtx,
    SC: ShardContext<GC>,
    Pcs: MultilinearPcsProver<GC, PcsProof<GC, SC>> + DefaultJaggedProver<GC, SC::Config>,
{
    fn from_shard_verifier(verifier: ShardVerifier<GC, SC>) -> Self {
        ShardProver::new(verifier)
    }
}

impl<SC, C> CoreProver<SC> for C
where
    SC: ShardContext<SP1GlobalContext, Config = SP1Pcs<SP1GlobalContext>>,
    SC::Air: MachineAir<SP1Field, Record = ExecutionRecord, Program = Program>,
    C: AirProver<SP1GlobalContext, SC>,
{
}

pub trait RecursionProver: AirProver<SP1GlobalContext, RecursionSC> {
    fn verifier() -> MachineVerifier<SP1GlobalContext, RecursionSC> {
        let compress_log_stacking_height = RECURSION_LOG_STACKING_HEIGHT;
        let compress_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

        let machine = CompressAir::<SP1Field>::compress_machine();
        let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
            recursion_fri_config(),
            compress_log_stacking_height,
            compress_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(recursion_shard_verifier)
    }

    fn shrink_verifier() -> MachineVerifier<SP1GlobalContext, ShrinkSC> {
        let shrink_log_stacking_height = SHRINK_LOG_STACKING_HEIGHT;
        let shrink_max_log_row_count = SHRINK_MAX_LOG_ROW_COUNT;

        let machine = CompressAir::<SP1Field>::shrink_machine();
        let recursion_shard_verifier = ShardVerifier::from_basefold_parameters(
            shrink_fri_config(),
            shrink_log_stacking_height,
            shrink_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(recursion_shard_verifier)
    }
}

pub trait WrapProver: AirProver<SP1OuterGlobalContext, WrapSC> {
    fn wrap_verifier() -> MachineVerifier<SP1OuterGlobalContext, WrapSC> {
        let wrap_log_stacking_height = WRAP_LOG_STACKING_HEIGHT;
        let wrap_max_log_row_count = RECURSION_MAX_LOG_ROW_COUNT;

        let machine = WrapAir::<SP1Field>::wrap_machine();
        let wrap_shard_verifier = ShardVerifier::from_basefold_parameters(
            wrap_fri_config(),
            wrap_log_stacking_height,
            wrap_max_log_row_count,
            machine.clone(),
        );

        MachineVerifier::new(wrap_shard_verifier)
    }
}

impl<C> RecursionProver for C where C: AirProver<SP1GlobalContext, RecursionSC> {}

impl<C> WrapProver for C where C: AirProver<SP1OuterGlobalContext, WrapSC> {}

pub trait SP1ProverComponents: Send + Sync + Clone + 'static
where
    Self::CoreProver: CoreAirProverFactory<SP1GlobalContext, Self::CoreSC>,
    Self::RecursionProver: CoreAirProverFactory<SP1GlobalContext, RecursionSC>,
    Self::WrapProver: CoreAirProverFactory<SP1OuterGlobalContext, WrapSC>,
    Self::CoreSC: ShardContext<SP1GlobalContext, Config = SP1Pcs<SP1GlobalContext>>,
    <Self::CoreSC as ShardContext<SP1GlobalContext>>::Air: for<'b> Air<RecursiveVerifierConstraintFolder<'b>>
        + MachineAir<SP1Field, Record = ExecutionRecord, Program = Program>,
{
    type CoreSC: ShardContext<SP1GlobalContext, Config = SP1Pcs<SP1GlobalContext>>;
    /// The prover for making SP1 core proofs.
    type CoreProver: CoreProver<Self::CoreSC>;
    /// The prover for making SP1 recursive proofs.
    type RecursionProver: RecursionProver;
    type WrapProver: WrapProver;

    fn core_verifier(
        machine: Machine<SP1Field, <Self::CoreSC as ShardContext<SP1GlobalContext>>::Air>,
    ) -> MachineVerifier<SP1GlobalContext, Self::CoreSC> {
        <Self::CoreProver as CoreProver<Self::CoreSC>>::verifier(machine)
    }

    fn compress_verifier() -> MachineVerifier<SP1GlobalContext, RecursionSC> {
        <Self::RecursionProver as RecursionProver>::verifier()
    }

    fn shrink_verifier() -> MachineVerifier<SP1GlobalContext, ShrinkSC> {
        <Self::RecursionProver as RecursionProver>::shrink_verifier()
    }

    fn wrap_verifier() -> MachineVerifier<SP1OuterGlobalContext, WrapSC> {
        <Self::WrapProver as WrapProver>::wrap_verifier()
    }
}

#[derive(Clone, Copy)]
pub struct CpuSP1ProverComponents;

impl SP1ProverComponents for CpuSP1ProverComponents {
    type CoreSC = CoreSC;
    type CoreProver = CpuShardProver<
        SP1GlobalContext,
        SP1Pcs<SP1GlobalContext>,
        SP1InnerPcsProver,
        RiscvAir<SP1Field>,
    >;
    type RecursionProver =
        CpuShardProver<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, CompressAir<SP1Field>>;
    type WrapProver =
        CpuShardProver<SP1OuterGlobalContext, SP1OuterPcs, SP1OuterPcsProver, WrapAir<SP1Field>>;
}

#[derive(Clone, Copy)]
pub struct CpuSP1ApcProverComponents;

impl SP1ProverComponents for CpuSP1ApcProverComponents {
    type CoreSC = CoreSCWithApcs;
    type CoreProver = CpuShardProver<
        SP1GlobalContext,
        SP1Pcs<SP1GlobalContext>,
        SP1InnerPcsProver,
        RiscvAirWithApcs<SP1Field>,
    >;
    type RecursionProver =
        CpuShardProver<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, CompressAir<SP1Field>>;
    type WrapProver =
        CpuShardProver<SP1OuterGlobalContext, SP1OuterPcs, SP1OuterPcsProver, WrapAir<SP1Field>>;
}
