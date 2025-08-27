use core::panic;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use itertools::Itertools;
use powdr_autoprecompiles::{
    blocks::Program as _,
    expression::{AlgebraicExpression, AlgebraicReference},
    Apc,
};
use powdr_expression::{AlgebraicBinaryOperator, AlgebraicUnaryOperator};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{
    events::ByteLookupEvent, opcode::ByteOpcode, ApcRange, ExecutionRecord, Program,
};
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, MessageBuilder, SP1AirBuilder},
    InteractionKind, Machine,
};

use crate::{
    autoprecompiles::{
        instruction::Sp1Instruction,
        instruction_handler::{try_instruction_type_to_air_id, InstructionType},
        program::Sp1Program,
    },
    riscv::RiscvAir,
    utils::{next_multiple_of_32, pad_rows_fixed},
};

#[derive(Debug)]
struct CachedApc<F: PrimeField32> {
    /// The APC
    apc: Arc<Apc<F, Sp1Instruction>>,
    /// The cached columns of the APC.
    columns: Vec<AlgebraicReference>,
}

impl<F: PrimeField32> CachedApc<F> {
    /// The width of the APC.
    pub fn width(&self) -> usize {
        self.columns.len()
    }
}

impl<F: PrimeField32> From<Arc<Apc<F, Sp1Instruction>>> for CachedApc<F> {
    fn from(apc: Arc<Apc<F, Sp1Instruction>>) -> Self {
        let columns = apc.machine.main_columns().collect();
        Self { apc, columns }
    }
}

#[derive(Debug)]
pub struct ApcChip<F: PrimeField32> {
    /// The ID of the APC.
    id: u64,
    /// The cached APC.
    cached_apc: CachedApc<F>,
    /// A machine to generate traces for the APC.
    machine: Machine<F, RiscvAir<F>>,
}

impl<F: PrimeField32> ApcChip<F> {
    pub fn new(apc: Arc<Apc<F, Sp1Instruction>>, id: usize) -> Self {
        Self { id: id as u64, cached_apc: apc.into(), machine: RiscvAir::machine() }
    }

    pub fn apc(&self) -> &Arc<Apc<F, Sp1Instruction>> {
        &self.cached_apc.apc
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl<F: PrimeField32> BaseAir<F> for ApcChip<F> {
    fn width(&self) -> usize {
        self.cached_apc.width()
    }
}

impl<F: PrimeField32> MachineAir<F> for ApcChip<F> {
    // this may have to be changed
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("ApcChip_{}", self.id)
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let num_apc_events = input.get_apc_events(self.id).map_or(0, |events| events.len());
        let nb_rows = next_multiple_of_32(num_apc_events, input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Get all events for the given APC ID
        let events = input.get_apc_events(self.id).expect("APC events not found");

        // Mapping from poly_id to contiguous index in apc
        let apc_poly_id_to_index = self
            .apc()
            .machine
            .main_columns()
            .enumerate()
            .map(|(index, c)| (c.id, index))
            .collect::<BTreeMap<_, _>>();

        // Get is_valid_index to manually fill with 1 for witness generation
        let is_valid_column =
            self.apc().machine.main_columns().find(|c| &*c.name == "is_valid").unwrap();
        let is_valid_index = apc_poly_id_to_index[&is_valid_column.id];

        // Turn each event into a row
        // TODO: can we do this for all events at the same time? Basically combine all events into a
        // single record, and run trace generation for that?
        let mut rows = events
            .par_iter()
            .map(|event| {
                assert!(event.id == self.id, "APC ID mismatch");
                let airs = self.machine.chips().to_vec();

                // Generate traces for each included air in parallel
                let chips_and_traces = airs
                    .into_par_iter()
                    .filter(|air| air.included(&event.record))
                    .map(|air| {
                        let trace = air.generate_trace(&event.record, &mut Default::default());
                        (air, trace)
                    })
                    .collect::<BTreeMap<_, _>>();

                // Create iterators over the rows of the traces
                let mut iterators = chips_and_traces
                    .iter()
                    .map(|(chip, trace)| (chip.air.id(), trace.rows()))
                    .collect::<BTreeMap<_, _>>();

                // Create a row for the APC
                let mut row = vec![F::zero(); self.width()];

                // Go through the original instructions of the APC and map the relevant rows to the APC row
                let original_instructions = self.apc().block.statements.iter().map(|instr| instr.0);

                for (original_instruction, sub) in original_instructions.zip_eq(&self.apc().subs) {
                    // Get the air ID for the instruction
                    let air_id = try_instruction_type_to_air_id(InstructionType::from(original_instruction))
                        .expect("Invalid instruction as an original instruction in an APC: {original_instruction:?}");
                    tracing::trace!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        });
                    tracing::trace!("Original row: {original_row:?}");
                    // Map the row to the APC row
                    for (value, poly_id) in original_row.zip_eq(sub) {
                        // get index in apc from poly_id
                        if let Some(index) = apc_poly_id_to_index.get(poly_id) {
                            tracing::trace!("Setting row[{index}] to {value:?}");
                            row[*index] = value;
                        } else {
                            tracing::trace!("Poly ID {poly_id} not found in APC columns (usually due to optimization)");
                        }
                    }
                }

                // Manually set is_valid column to 1
                row[is_valid_index] = F::one();

                tracing::trace!("Final row: {row:?}");

                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); self.width()],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Assert number of rows is correct
        assert_eq!(rows.len(), <ApcChip<F> as MachineAir<F>>::num_rows(self, input).unwrap());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), self.width())
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        // Get all events for the given APC ID
        let events = input.get_apc_events(self.id);
        // Because `generate_dependencies` is run during execution for all chips, it's not
        // guaranteed that there will be APC events at all.
        if events.is_none() {
            tracing::debug!(
                "No APC events found for APC ID during `generate_dependencies`: {}",
                self.id
            );
            return; // Early return because no dependencies to generate.
        }
        let events = events.unwrap();

        // Mapping from poly_id to contiguous index in apc
        let apc_poly_id_to_index = self
            .apc()
            .machine
            .main_columns()
            .enumerate()
            .map(|(index, c)| (c.id, index))
            .collect::<BTreeMap<_, _>>();

        // Get is_valid_index to manually fill with 1 for witness generation
        let is_valid_column =
            self.apc().machine.main_columns().find(|c| &*c.name == "is_valid").unwrap();
        let is_valid_index = apc_poly_id_to_index[&is_valid_column.id];

        // Turn each event into a row and collect byte/range check side effects to reapply as events
        // to ExecutionRecord
        // TODO: can we combine all events into a single record, and run trace generation a
        // single time?
        let byte_interactions_deltas = events
            .par_iter()
            .map(|event| {
                assert!(event.id == self.id, "APC ID mismatch");
                let airs = self.machine.chips().to_vec();

                // Generate traces for each included air in parallel
                let chips_and_traces = airs
                    .into_par_iter()
                    .filter(|air| air.included(&event.record))
                    .map(|air| {
                        let trace = air.generate_trace(&event.record, &mut Default::default());
                        (air, trace)
                    })
                    .collect::<BTreeMap<_, _>>();

                // Create iterators over the rows of the traces
                let mut iterators = chips_and_traces
                    .iter()
                    .map(|(chip, trace)| (chip.air.id(), trace.rows()))
                    .collect::<BTreeMap<_, _>>();

                // Create a row for the APC
                let mut row = vec![F::zero(); self.width()];

                // Go through the original instructions of the APC and map the relevant rows to the APC row
                let original_instructions = self.apc().block.statements.iter().map(|instr| instr.0);

                for (original_instruction, sub) in original_instructions.zip_eq(&self.apc().subs) {
                    // Get the air ID for the instruction
                    let air_id = try_instruction_type_to_air_id(InstructionType::from(original_instruction))
                        .expect("Invalid instruction as an original instruction in an APC: {original_instruction:?}");
                    tracing::trace!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        });
                    tracing::trace!("Original row: {original_row:?}");
                    // Map the row to the APC row
                    for (value, poly_id) in original_row.zip_eq(sub) {
                        // get index in apc from poly_id
                        if let Some(index) = apc_poly_id_to_index.get(poly_id) {
                            tracing::trace!("Setting row[{index}] to {value:?}");
                            row[*index] = value;
                        } else {
                            tracing::trace!("Poly ID {poly_id} not found in APC columns (usually due to optimization)");
                        }
                    }

                    // Manually set is_valid column to 1
                    row[is_valid_index] = F::one();
                }

                // Collect and replay side effects as events
                // Only need to do this for byte lookup bus, as other buses are implicitly balanced via main trace values rather than via events
                let mut byte_interactions_delta = HashMap::new(); // map of event to sum of multiplicities

                let evaluator = RowEvaluator::new(&row, Some(&apc_poly_id_to_index));

                for bus_interaction in self.apc().machine.bus_interactions.iter() {
                    let mult = evaluator
                        .eval_expr(&bus_interaction.mult)
                        .as_canonical_u32();
                    let args = bus_interaction
                        .args
                        .iter()
                        .map(|arg| evaluator.eval_expr(arg).as_canonical_u32())
                        .collect_vec();

                    if bus_interaction.id == InteractionKind::Byte as u64 { // byte lookup
                        assert_eq!(args.len(), 4);
                        *byte_interactions_delta.entry(ByteLookupEvent {
                            opcode: match args[0] {
                                0 => ByteOpcode::AND,
                                1 => ByteOpcode::OR,
                                2 => ByteOpcode::XOR,
                                3 => ByteOpcode::U8Range,
                                4 => ByteOpcode::LTU,
                                5 => ByteOpcode::MSB,
                                6 => ByteOpcode::Range,
                                _ => unreachable!("Unexpected byte lookup Opcode: {}", args[0]),
                            },
                            a: args[1] as u16,
                            b: args[2] as u8,
                            c: args[3] as u8,
                        }).or_insert(0) += mult as isize;
                    }
                }

                tracing::trace!("Final row: {row:?}");

                byte_interactions_delta
            })
            .collect::<Vec<_>>();

        // Replay byte lookups (can only mutate output after map)
        for delta in byte_interactions_deltas.into_iter() {
            for (event, mult) in delta.into_iter() {
                *output.byte_lookups.entry(event).or_insert(0) += mult;
            }
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.apc_events.is_empty()
        }
    }

    fn customize_program(&self, program: Self::Program) -> Self::Program {
        let range = ApcRange::new(
            ((self.apc().start_pc() - program.pc_base) / Sp1Program::default().pc_step() as u64)
                as usize,
            self.apc().block.statements.len(),
        );
        program.add_apc(range)
    }
}

impl<AB: SP1AirBuilder + PairBuilder + MessageBuilder<AirInteraction<AB::Expr>>> Air<AB>
    for ApcChip<AB::F>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let witnesses = main.row_slice(0);

        let witness_values: BTreeMap<u64, AB::Var> = self
            .cached_apc
            .columns
            .iter()
            .map(|c| c.id)
            .zip_eq(witnesses.iter().cloned())
            .collect();

        let witness_evaluator = WitnessEvaluator::<AB>::new(&witness_values);

        for constraint in &self.cached_apc.apc.machine().constraints {
            let e = witness_evaluator.eval_expr(&constraint.expr);
            builder.assert_zero(e);
        }

        for interaction in &self.cached_apc.apc.machine().bus_interactions {
            let powdr_autoprecompiles::SymbolicBusInteraction { mult, args, id } = interaction;

            let mult = witness_evaluator.eval_expr(mult);
            let args = args.iter().map(|arg| witness_evaluator.eval_expr(arg)).collect_vec();

            // All instruction AIRs only use the four buses below.
            let interaction_kind = match id {
                id if *id == InteractionKind::Memory as u64 => InteractionKind::Memory,
                id if *id == InteractionKind::Program as u64 => InteractionKind::Program,
                id if *id == InteractionKind::Byte as u64 => InteractionKind::Byte,
                id if *id == InteractionKind::State as u64 => InteractionKind::State,
                _ => unreachable!("Unexpected bus ID: {id}"),
            };

            let air_interaction = AirInteraction::new(args, mult, interaction_kind);

            // We only need to send, because receive is just send with negative multiplicity.
            builder.send(air_interaction, InteractionScope::Local);
        }
    }
}

pub struct WitnessEvaluator<'a, AB: AirBuilder> {
    pub witness: &'a BTreeMap<u64, AB::Var>,
}

impl<'a, AB: AirBuilder> WitnessEvaluator<'a, AB> {
    pub fn new(witness: &'a BTreeMap<u64, AB::Var>) -> Self {
        Self { witness }
    }
}

impl<AB: AirBuilder> WitnessEvaluator<'_, AB> {
    fn eval_const(&self, c: AB::F) -> AB::Expr {
        c.into()
    }

    fn eval_var(&self, symbolic_var: AlgebraicReference) -> AB::Expr {
        (*self.witness.get(&(symbolic_var.id as u64)).unwrap()).into()
    }

    fn eval_expr(&self, algebraic_expr: &AlgebraicExpression<AB::F>) -> AB::Expr {
        match algebraic_expr {
            AlgebraicExpression::Number(n) => self.eval_const(*n),
            AlgebraicExpression::BinaryOperation(binary) => match binary.op {
                AlgebraicBinaryOperator::Add => {
                    self.eval_expr(&binary.left) + self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Sub => {
                    self.eval_expr(&binary.left) - self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Mul => {
                    self.eval_expr(&binary.left) * self.eval_expr(&binary.right)
                }
            },
            AlgebraicExpression::UnaryOperation(unary) => match unary.op {
                AlgebraicUnaryOperator::Minus => -self.eval_expr(&unary.expr),
            },
            AlgebraicExpression::Reference(var) => self.eval_var(var.clone()),
        }
    }
}

pub struct RowEvaluator<'a, F: PrimeField32> {
    pub row: &'a [F],
    pub witness_id_to_index: Option<&'a BTreeMap<u64, usize>>,
}

impl<'a, F: PrimeField32> RowEvaluator<'a, F> {
    pub fn new(row: &'a [F], witness_id_to_index: Option<&'a BTreeMap<u64, usize>>) -> Self {
        Self { row, witness_id_to_index }
    }

    fn eval_expr(&self, algebraic_expr: &AlgebraicExpression<F>) -> F {
        match algebraic_expr {
            AlgebraicExpression::Number(n) => self.eval_const(*n),
            AlgebraicExpression::BinaryOperation(binary) => match binary.op {
                AlgebraicBinaryOperator::Add => {
                    self.eval_expr(&binary.left) + self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Sub => {
                    self.eval_expr(&binary.left) - self.eval_expr(&binary.right)
                }
                AlgebraicBinaryOperator::Mul => {
                    self.eval_expr(&binary.left) * self.eval_expr(&binary.right)
                }
            },
            AlgebraicExpression::UnaryOperation(unary) => match unary.op {
                AlgebraicUnaryOperator::Minus => -self.eval_expr(&unary.expr),
            },
            AlgebraicExpression::Reference(var) => self.eval_var(var.clone()),
        }
    }

    fn eval_const(&self, c: F) -> F {
        c
    }

    fn eval_var(&self, algebraic_var: AlgebraicReference) -> F {
        let index = if let Some(witness_id_to_index) = self.witness_id_to_index {
            witness_id_to_index[&(algebraic_var.id)]
        } else {
            algebraic_var.id as usize
        };
        self.row[index]
    }
}
