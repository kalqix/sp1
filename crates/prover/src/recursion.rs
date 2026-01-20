use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    path::PathBuf,
};

<<<<<<< HEAD
use slop_air::Air;
use slop_algebra::{extension::BinomialExtensionField, AbstractField, PrimeField32};
use slop_jagged::JaggedConfig;
use sp1_core_executor::SP1RecursionProof;
=======
use slop_algebra::{AbstractField, PrimeField32};
use slop_challenger::IopCtx;
use sp1_core_machine::riscv::RiscvAir;
>>>>>>> origin/multilinear_v6
use sp1_hypercube::{
    air::{POSEIDON_NUM_WORDS, PROOF_NONCE_NUM_WORDS},
    prover::ZerocheckAir,
    verify_merkle_proof, HashableKey, MachineVerifier, MachineVerifyingKey, MerkleProof,
    SP1InnerPcs, SP1PcsProofInner, ShardVerifier, SP1SC,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use sp1_recursion_circuit::{
    basefold::{
        merkle_tree::MerkleTree, stacked::RecursiveStackedPcsVerifier, tcs::RecursiveMerkleTreeTcs,
        RecursiveBasefoldVerifier,
    },
    jagged::{RecursiveJaggedEvalSumcheckConfig, RecursiveJaggedPcsVerifier},
    machine::{
        InnerVal, PublicValuesOutputDigest, SP1CompressRootVerifierWithVKey,
        SP1CompressWithVKeyVerifier, SP1CompressWithVKeyWitnessValues, SP1DeferredVerifier,
        SP1DeferredWitnessValues, SP1NormalizeWitnessValues, SP1RecursiveVerifier,
    },
    shard::RecursiveShardVerifier,
    witness::Witnessable,
    zerocheck::RecursiveVerifierConstraintFolder,
    CircuitConfig, SP1FieldConfigVariable, WrapConfig as CircuitWrapConfig,
};
use sp1_recursion_compiler::{
    circuit::AsmCompiler,
    config::InnerConfig,
    ir::{Builder, DslIrProgram},
};
use sp1_recursion_executor::{RecursionProgram, DIGEST_SIZE};

use crate::{
    shapes::{create_all_input_shapes, SP1RecursionProofShape},
    worker::{TaskError, DEFAULT_MAX_COMPOSE_ARITY},
    CompressAir, RecursionSC,
};

<<<<<<< HEAD
pub mod components;
pub use components::*;

type RecursionConfig<C> =
    <<C as SP1ProverComponents>::RecursionComponents as MachineProverComponents>::Config;

type RecursionF<C> =
    <<C as SP1ProverComponents>::RecursionComponents as MachineProverComponents>::F;

type WrapConfig<C> =
    <<C as SP1ProverComponents>::WrapComponents as MachineProverComponents>::Config;

#[allow(clippy::type_complexity)]
pub struct SP1RecursionProver<C: SP1ProverComponents> {
    pub(crate) prover: MachineProver<C::RecursionComponents>,
    pub(crate) shrink_prover: MachineProver<C::RecursionComponents>,
    wrap_prover: MachineProver<C::WrapComponents>,
    pub(crate) core_verifier:
        MachineVerifier<CoreSC, <C::CoreComponents as MachineProverComponents>::Air>,
    pub(crate) normalize_program_cache:
        SP1NormalizeCache<<C::CoreComponents as MachineProverComponents>::Air>,
    reduce_shape: SP1RecursionProofShape,
    compose_programs: BTreeMap<usize, Arc<RecursionProgram<SP1Field>>>,
    compose_keys: BTreeMap<
        usize,
        (Arc<MachineProvingKey<C::RecursionComponents>>, MachineVerifyingKey<RecursionConfig<C>>),
    >,
    deferred_program: Option<Arc<RecursionProgram<SP1Field>>>,
    deferred_keys: Option<(
        Arc<MachineProvingKey<C::RecursionComponents>>,
        MachineVerifyingKey<RecursionConfig<C>>,
    )>,
    shrink_program: Arc<RecursionProgram<SP1Field>>,
    shrink_keys: Mutex<
        Option<(
            Arc<MachineProvingKey<C::RecursionComponents>>,
            MachineVerifyingKey<RecursionConfig<C>>,
        )>,
    >,
    wrap_program: Arc<RecursionProgram<SP1Field>>,
    wrap_keys: Mutex<
        Option<(Arc<MachineProvingKey<C::WrapComponents>>, MachineVerifyingKey<WrapConfig<C>>)>,
    >,
    pub recursive_core_verifier: RecursiveShardVerifier<
        <C::CoreComponents as MachineProverComponents>::Air,
        CoreSC,
        InnerConfig,
        JC<InnerConfig, CoreSC>,
    >,
    pub(crate) recursive_compress_verifier: RecursiveShardVerifier<
        CompressAir<InnerVal>,
        InnerSC,
        InnerConfig,
        JC<InnerConfig, InnerSC>,
    >,
    /// The root of the allowed recursion verification keys.
    pub recursion_vk_root: <InnerSC as FieldHasher<SP1Field>>::Digest,
    /// The allowed vks and their corresponding indices.
    pub recursion_vk_map: BTreeMap<<InnerSC as FieldHasher<SP1Field>>::Digest, usize>,
    /// The merkle root of allowed vks.
    pub recursion_vk_tree: MerkleTree<SP1Field, InnerSC>,
    /// Whether to verify the vk.
=======
#[derive(Clone)]
pub struct RecursionVks {
    root: <SP1GlobalContext as IopCtx>::Digest,
    map: BTreeMap<<SP1GlobalContext as IopCtx>::Digest, usize>,
    tree: MerkleTree<SP1GlobalContext>,
>>>>>>> origin/multilinear_v6
    vk_verification: bool,
}

<<<<<<< HEAD
impl<C: SP1ProverComponents> SP1RecursionProver<C>
where
    <C::CoreComponents as MachineProverComponents>::Air:
        for<'b> Air<RecursiveVerifierConstraintFolder<'b, InnerConfig>>,
{
    pub async fn new(
        core_verifier: ShardVerifier<
            CoreSC,
            <<C as SP1ProverComponents>::CoreComponents as MachineProverComponents>::Air,
        >,
        prover: MachineProver<C::RecursionComponents>,
        shrink_prover: MachineProver<C::RecursionComponents>,
        wrap_prover: MachineProver<C::WrapComponents>,
        normalize_programs_cache_size: usize,
        normalize_programs: BTreeMap<
            SP1NormalizeInputShape<
                <<C as SP1ProverComponents>::CoreComponents as MachineProverComponents>::Air,
            >,
            Arc<RecursionProgram<SP1Field>>,
        >,
=======
impl Default for RecursionVks {
    fn default() -> Self {
        Self::new(None, DEFAULT_MAX_COMPOSE_ARITY, true)
    }
}

impl RecursionVks {
    /// The map for the recursion vk hashes to their indice in the merkle tree.
    const RECURSION_VK_MAP_BYTES: &[u8] = include_bytes!("vk_map.bin");

    fn from_map(
        mut map: BTreeMap<[SP1Field; DIGEST_SIZE], usize>,
>>>>>>> origin/multilinear_v6
        max_compose_arity: usize,
        vk_verification: bool,
    ) -> Self {
        // Pad the map to the expected number of shapes. This allows us to build partial vk maps
        // for development purposes.
        let num_shapes = create_all_input_shapes(RiscvAir::machine().shape(), max_compose_arity)
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len();

        let added_len = num_shapes.saturating_sub(map.len());
        let prev_len = map.len();

        map.extend((0..added_len).map(|i| {
            let index = i + prev_len;
            ([SP1Field::from_canonical_u32(index as u32); DIGEST_SIZE], index)
        }));

        let vks = map.into_keys().collect::<BTreeSet<_>>();
        let map: BTreeMap<_, _> = vks.into_iter().enumerate().map(|(i, vk)| (vk, i)).collect();

        // Commit the merkle tree.
        let (root, tree) = MerkleTree::<SP1GlobalContext>::commit(map.keys().copied().collect());

        Self { root, map, tree, vk_verification }
    }

    fn dummy(max_compose_arity: usize) -> Self {
        Self::from_map(BTreeMap::new(), max_compose_arity, false)
    }

    fn from_file(path: PathBuf, max_compose_arity: usize, vk_verification: bool) -> Self {
        let file = std::fs::File::open(path).expect("failed to open vk map file");
        let map = bincode::deserialize_from(file).expect("failed to deserialize vk map");
        Self::from_map(map, max_compose_arity, vk_verification)
    }

    pub fn new(path: Option<PathBuf>, max_compose_arity: usize, vk_verification: bool) -> Self {
        if !vk_verification {
            return Self::dummy(max_compose_arity);
        }

        if let Some(path) = path {
            return Self::from_file(path, max_compose_arity, vk_verification);
        }

        let map = bincode::deserialize(Self::RECURSION_VK_MAP_BYTES)
            .expect("failed to deserialize vk map");
        Self::from_map(map, max_compose_arity, vk_verification)
    }

    pub fn root(&self) -> <SP1GlobalContext as IopCtx>::Digest {
        self.root
    }

    pub fn contains(&self, vk: &MachineVerifyingKey<SP1GlobalContext>) -> bool {
        self.map.contains_key(&vk.hash_koalabear())
    }

    pub fn num_keys(&self) -> usize {
        self.map.len()
    }

    /// Whether to verify the recursion vks.
    pub fn vk_verification(&self) -> bool {
        self.vk_verification
    }

    pub fn open(
        &self,
        vk: &MachineVerifyingKey<SP1GlobalContext>,
    ) -> Result<([SP1Field; DIGEST_SIZE], MerkleProof<SP1GlobalContext>), TaskError> {
        let index = if self.vk_verification {
            let digest = vk.hash_koalabear();
            let index = self
                .map
                .get(&digest)
                .copied()
                .ok_or(TaskError::Fatal(anyhow::anyhow!("vk not allowed")))?;
            index
        } else {
            let vk_digest = vk.hash_koalabear();
            let num_vks = self.num_keys();
            (vk_digest[0].as_canonical_u32() as usize) % num_vks
        };

        let (value, proof) = MerkleTree::open(&self.tree, index);
        // Verify the proof.
        verify_merkle_proof(&proof, value, self.root)
            .map_err(|e| TaskError::Fatal(anyhow::anyhow!("invalid merkle proof: {:?}", e)))?;
        Ok((value, proof))
    }

    pub fn verify(
        &self,
        proof: &MerkleProof<SP1GlobalContext>,
        vk: &MachineVerifyingKey<SP1GlobalContext>,
    ) -> Result<(), TaskError> {
        let digest = vk.hash_koalabear();
        verify_merkle_proof(proof, digest, self.root)
            .map_err(|e| TaskError::Fatal(anyhow::anyhow!("invalid merkle proof: {:?}", e)))
    }

    pub fn height(&self) -> usize {
        self.tree.height
    }
}

/// The program that proves the correct execution of the verifier of a single shard of the core
/// (RISC-V) machine.
<<<<<<< HEAD
pub fn normalize_program_from_input<
    A: MachineAir<SP1Field> + for<'b> Air<RecursiveVerifierConstraintFolder<'b, InnerConfig>>,
>(
    recursive_verifier: &RecursiveShardVerifier<A, CoreSC, InnerConfig, JC<InnerConfig, CoreSC>>,
    input: &SP1NormalizeWitnessValues<CoreSC>,
=======
pub fn normalize_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<SP1GlobalContext, RiscvAir<SP1Field>, InnerConfig>,
    input: &SP1NormalizeWitnessValues<SP1GlobalContext, SP1PcsProofInner>,
>>>>>>> origin/multilinear_v6
) -> RecursionProgram<SP1Field> {
    // Get the operations.
    let builder_span = tracing::debug_span!("build recursion program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_variable = input.read(&mut builder);
    SP1RecursiveVerifier::<InnerConfig>::verify(&mut builder, recursive_verifier, input_variable);
    let block = builder.into_root_block();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };
    builder_span.exit();

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile recursion program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The deferred program.
pub(crate) fn deferred_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1DeferredWitnessValues<SP1GlobalContext, SP1PcsProofInner>,
) -> RecursionProgram<SP1Field> {
    // Get the operations.
    let operations_span = tracing::debug_span!("get operations for the deferred program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    let input_read_span = tracing::debug_span!("Read input values").entered();
    let input = input.read(&mut builder);
    input_read_span.exit();
    let verify_span = tracing::debug_span!("Verify deferred program").entered();

    // Verify the proof.
    SP1DeferredVerifier::verify(&mut builder, recursive_verifier, input, vk_verification);
    verify_span.exit();
    let block = builder.into_root_block();
    operations_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    let compiler_span = tracing::debug_span!("compile deferred program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The "compose" program, which verifies some number of normalized shard proofs.
pub(crate) fn compose_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build compress program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the proof.
    SP1CompressWithVKeyVerifier::<InnerConfig, SP1InnerPcs, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Reduce,
    );
    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile compress program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();
    program
}

/// The "shrink" program, which only verifies the single root shard.
pub(crate) fn shrink_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        InnerConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build shrink program").entered();
    let mut builder = Builder::<InnerConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the root proof.
    SP1CompressRootVerifierWithVKey::<InnerConfig, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Reduce,
    );

    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile shrink program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();

    program
}

/// The "wrap" program, which only verifies the single root shard.
pub(crate) fn wrap_program_from_input(
    recursive_verifier: &RecursiveShardVerifier<
        SP1GlobalContext,
        CompressAir<InnerVal>,
        CircuitWrapConfig,
    >,
    vk_verification: bool,
    input: &SP1CompressWithVKeyWitnessValues<SP1PcsProofInner>,
) -> RecursionProgram<SP1Field> {
    let builder_span = tracing::debug_span!("build wrap program").entered();
    let mut builder = Builder::<CircuitWrapConfig>::default();
    // read the input.
    let input = input.read(&mut builder);

    // Verify the root proof.
    SP1CompressRootVerifierWithVKey::<CircuitWrapConfig, _>::verify(
        &mut builder,
        recursive_verifier,
        input,
        vk_verification,
        PublicValuesOutputDigest::Root,
    );

    let block = builder.into_root_block();
    builder_span.exit();
    // SAFETY: The circuit is well-formed. It does not use synchronization primitives
    // (or possibly other means) to violate the invariants.
    let dsl_program = unsafe { DslIrProgram::new_unchecked(block) };

    // Compile the program.
    let compiler_span = tracing::debug_span!("compile wrap program").entered();
    let mut compiler = AsmCompiler::default();
    let program = compiler.compile(dsl_program);
    compiler_span.exit();

    program
}

pub(crate) fn dummy_compose_input(
    verifier: &MachineVerifier<SP1GlobalContext, RecursionSC>,
    shape: &SP1RecursionProofShape,
    arity: usize,
    height: usize,
) -> SP1CompressWithVKeyWitnessValues<SP1PcsProofInner> {
    let chips =
        verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>();

    let max_log_row_count = verifier.max_log_row_count();
    let log_stacking_height = verifier.log_stacking_height() as usize;

    shape.dummy_input(
        arity,
        height,
        chips,
        max_log_row_count,
        *verifier.fri_config(),
        log_stacking_height,
    )
}

pub(crate) fn dummy_deferred_input(
    verifier: &MachineVerifier<SP1GlobalContext, RecursionSC>,
    shape: &SP1RecursionProofShape,
    height: usize,
) -> SP1DeferredWitnessValues<SP1GlobalContext, SP1PcsProofInner> {
    let chips =
        verifier.shard_verifier().machine().chips().iter().cloned().collect::<BTreeSet<_>>();

    let max_log_row_count = verifier.max_log_row_count();
    let log_stacking_height = verifier.log_stacking_height() as usize;

    let compress_input = shape.dummy_input(
        1,
        height,
        chips,
        max_log_row_count,
        *verifier.fri_config(),
        log_stacking_height,
    );

    SP1DeferredWitnessValues {
        vks_and_proofs: compress_input.compress_val.vks_and_proofs,
        vk_merkle_data: compress_input.merkle_val,
        start_reconstruct_deferred_digest: [SP1Field::zero(); POSEIDON_NUM_WORDS],
        sp1_vk_digest: [SP1Field::zero(); DIGEST_SIZE],
        end_pc: [SP1Field::zero(); 3],
        proof_nonce: [SP1Field::zero(); PROOF_NONCE_NUM_WORDS],
        deferred_proof_index: SP1Field::zero(),
    }
}

pub(crate) fn recursive_verifier<GC, A, C>(
    shard_verifier: &ShardVerifier<GC, SP1SC<GC, A>>,
) -> RecursiveShardVerifier<GC, A, C>
where
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    A: ZerocheckAir<SP1Field, SP1ExtensionField>,
    C: CircuitConfig,
{
    let log_stacking_height = shard_verifier.log_stacking_height();
    let max_log_row_count = shard_verifier.max_log_row_count();
    let machine = shard_verifier.machine().clone();
    let pcs_verifier = RecursiveBasefoldVerifier {
        fri_config: shard_verifier.jagged_pcs_verifier.pcs_verifier.basefold_verifier.fri_config,
        tcs: RecursiveMerkleTreeTcs::<C, GC>(PhantomData),
    };
    let recursive_verifier = RecursiveStackedPcsVerifier::new(pcs_verifier, log_stacking_height);

    let recursive_jagged_verifier = RecursiveJaggedPcsVerifier {
        stacked_pcs_verifier: recursive_verifier,
        max_log_row_count,
        jagged_evaluator: RecursiveJaggedEvalSumcheckConfig::<GC>(PhantomData),
    };

    RecursiveShardVerifier {
        machine,
        pcs_verifier: recursive_jagged_verifier,
        _phantom: std::marker::PhantomData,
    }
}
