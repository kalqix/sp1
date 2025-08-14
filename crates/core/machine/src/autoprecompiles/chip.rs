use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use itertools::Itertools;
use powdr_autoprecompiles::{
    expression::{AlgebraicExpression, AlgebraicReference},
    Apc, InstructionHandler, SymbolicBusInteraction,
};
use powdr_expression::{
    AlgebraicBinaryOperation, AlgebraicBinaryOperator, AlgebraicUnaryOperation,
    AlgebraicUnaryOperator,
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use slop_air::{Air, AirBuilder, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{events::ByteLookupEvent, opcode::ByteOpcode, ExecutionRecord, Program};
use sp1_stark::{
    air::{AirInteraction, InteractionScope, MachineAir, MessageBuilder, SP1AirBuilder},
    InteractionKind, Machine,
};

use crate::{
    autoprecompiles::{
        instruction::Sp1Instruction,
        instruction_handler::{
            try_instruction_type_to_air_id, InstructionType, Sp1InstructionHandler,
        },
    },
    riscv::RiscvAir,
    utils::pad_rows_fixed,
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
    /// Original AIRs
    original_airs: Sp1InstructionHandler<F>,
}

impl<F: PrimeField32> ApcChip<F> {
    pub fn new(
        apc: Arc<Apc<F, Sp1Instruction>>,
        id: usize,
        original_airs: Sp1InstructionHandler<F>,
    ) -> Self {
        Self { id: id as u64, cached_apc: apc.into(), machine: RiscvAir::machine(), original_airs }
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
        "Apc".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(input.get_apc_events(self.id).len())
    }

    fn generate_trace(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Get all events for the given APC ID
        let events = input.get_apc_events(self.id);
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

                // mapping from poly_id to contiguous index in apc
                let apc_poly_id_to_index = self.apc()
                    .machine
                    .main_columns()
                    .enumerate()
                    .map(|(index, c)| (c.id, index))
                    .collect::<BTreeMap<_, _>>();

                for (original_instruction, sub) in original_instructions.zip_eq(&self.apc().subs) {
                    // Get the air ID for the instruction
                    let air_id = try_instruction_type_to_air_id(InstructionType::from(original_instruction))
                        .expect("Invalid instruction as an original instruction in an APC: {original_instruction:?}");
                    tracing::debug!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        })
                        .collect::<Vec<_>>();
                    tracing::debug!("Original row: {original_row:?}");
                    // Map the row to the APC row. TODO: use the mapping returned by apc generation.
                    for (i, value) in original_row.iter().enumerate() {
                        // get poly_id from sub
                        let poly_id = sub.get(i).expect("Not in dummy");
                        // get index in apc from poly_id
                        if let Some(index) = apc_poly_id_to_index.get(poly_id) {
                            tracing::debug!("Setting row[{index}] to {value:?}");
                            row[*index] = *value;
                        } else {
                            tracing::debug!("Poly ID {poly_id} not found in APC columns (usually due to optimization)");
                        }
                    }
                }

                tracing::debug!("Final row: {row:?}");

                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || vec![F::zero(); self.width()],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), self.width())
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        // TODO: here we should probably only generate the dependencies which were not optimised
        // away in the APC
        // Get all events for the given APC ID
        let events = input.get_apc_events(self.id);
        // Turn each event into a row
        // TODO: can we do this for all events at the same time? Basically combine all events into a
        // single record, and run trace generation for that?
        let (mut rows, byte_interactions_deltas): (Vec<_>, Vec<_>) = events
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

                // mapping from poly_id to contiguous index in apc
                let apc_poly_id_to_index = self.apc()
                    .machine
                    .main_columns()
                    .enumerate()
                    .map(|(index, c)| (c.id, index))
                    .collect::<BTreeMap<_, _>>();

                // get original interactions for side effects removal
                let byte_interaction_by_original_instruction: Vec<Vec<SymbolicBusInteraction<F>>> = self.apc().block.statements.iter().map(|instr| {
                    self.original_airs.get_instruction_air(instr).unwrap().bus_interactions.iter().filter_map(|interaction| {
                        if interaction.id == 5 {
                            Some(interaction.clone())
                        } else {
                            None
                        }
                    }).collect::<Vec<_>>()
                }).collect::<Vec<_>>();

                // remove and replay side effects
                // cannot directly modify `output`, because map cannot capture `output` as a mutable reference
                let mut byte_interactions_delta = HashMap::new(); // event to sum of multiplicities

                for ((original_instruction, sub), byte_interactions) in original_instructions.zip_eq(&self.apc().subs).zip_eq(byte_interaction_by_original_instruction) {
                    // Get the air ID for the instruction
                    let air_id = try_instruction_type_to_air_id(InstructionType::from(original_instruction))
                        .expect("Invalid instruction as an original instruction in an APC: {original_instruction:?}");
                    tracing::debug!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        })
                        .collect::<Vec<_>>();
                    tracing::debug!("Original row: {original_row:?}");
                    // Map the row to the APC row. TODO: use the mapping returned by apc generation.
                    for (i, value) in original_row.iter().enumerate() {
                        // get poly_id from sub
                        let poly_id = sub.get(i).expect("Not in dummy");
                        // get index in apc from poly_id
                        if let Some(index) = apc_poly_id_to_index.get(poly_id) {
                            tracing::debug!("Setting row[{index}] to {value:?}");
                            row[*index] = *value;
                        } else {
                            tracing::debug!("Poly ID {poly_id} not found in APC columns (usually due to optimization)");
                        }
                    }

                    // No column id needed as we are operating on dummy row.
                    let dummy_evaluator = RowEvaluator::new(&original_row, None);

                    for interaction in byte_interactions {
                        let mult = dummy_evaluator.eval_expr(&interaction.mult);
                        let args = interaction.args.iter().map(|arg| dummy_evaluator.eval_expr(arg)).collect_vec();
                        // interaction id is 5
                        println!("remove mult: {mult} args: {args:?}");
                        // remove byte lookup event
                        *byte_interactions_delta.entry(ByteLookupEvent {
                            opcode: match args[0].as_canonical_u32() {
                                0 => ByteOpcode::AND,
                                1 => ByteOpcode::OR,
                                2 => ByteOpcode::XOR,
                                3 => ByteOpcode::U8Range,
                                4 => ByteOpcode::LTU,
                                5 => ByteOpcode::MSB,
                                6 => ByteOpcode::Range,
                                _ => unreachable!("Unexpected byte lookup Opcode: {}", args[0].as_canonical_u32()),
                            },
                            a: args[1].as_canonical_u32() as u16,
                            b: args[2].as_canonical_u32() as u8,
                            c: args[3].as_canonical_u32() as u8,
                        }).or_insert(0) -= mult.as_canonical_u32() as isize;
                    }
                }

                // replay the side effects
                let evaluator = RowEvaluator::new(&row, Some(&apc_poly_id_to_index));

                for bus_interaction in self.apc().machine.bus_interactions.iter().filter(|interaction| interaction.id == 5) {
                    let mult = evaluator
                        .eval_expr(&bus_interaction.mult)
                        .as_canonical_u32();
                    let args = bus_interaction
                        .args
                        .iter()
                        .map(|arg| evaluator.eval_expr(arg).as_canonical_u32())
                        .collect_vec();

                    println!("add mult: {mult} args: {args:?}");
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

                tracing::debug!("Final row: {row:?}");

                (row, byte_interactions_delta)
            })
            .unzip();
        
        // print all byte lookups
        input.byte_lookups.iter().for_each(|(event, mult)| {
            println!("ByteLookupEvent: {event:?} with multiplicity {mult}");
        });

        // remove byte lookups (can only mutate output after map)
        for delta in byte_interactions_deltas.into_iter() {
            for (event, mult) in delta.into_iter() {
                println!("Modifying event: {event:?} with multiplicity {mult}");
                *output.byte_lookups.entry(event).or_insert(0) += mult;
            }
        }
    }

// Modifying event: ByteLookupEvent { 6, a: 0, b: 13, c: 0 } with multiplicity 0
// Modifying event: ByteLookupEvent { 0, a: 0, b: 29, c: 0 } with multiplicity 1
// Modifying event: ByteLookupEvent { 0, a: 9, b: 4, c: 0 } with multiplicity 1
// Modifying event: ByteLookupEvent { 0, a: 3, b: 28, c: 0 } with multiplicity 2013265920
// Modifying event: ByteLookupEvent { 0, a: 4, b: 29, c: 0 } with multiplicity 2013265920
// Modifying event: ByteLookupEvent { 6, a: 3, b: 16, c: 0 } with multiplicity 0
// Modifying event: ByteLookupEvent { 0, a: 2, b: 27, c: 0 } with multiplicity 2013265920
// Modifying event: ByteLookupEvent { 6, a: 2, b: 16, c: 0 } with multiplicity 0
// Modifying event: ByteLookupEvent { 6, a: 1, b: 16, c: 0 } with multiplicity 0
// Modifying event: ByteLookupEvent { 6, a: 0, b: 16, c: 0 } with multiplicity 0
// Modifying event: ByteLookupEvent { 0, a: 1, b: 0, c: 0 } with multiplicity 2013265920
// Modifying event: ByteLookupEvent { 0, a: 0, b: 27, c: 0 } with multiplicity 1
// Modifying event: ByteLookupEvent { 3, a: 0, b: 0, c: 0 } with multiplicity -2
// Modifying event: ByteLookupEvent { 0, a: 0, b: 28, c: 0 } with multiplicity 1

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.apc_events.is_empty()
        }
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

            println!("Processing AlgebraicExpression mult: {mult} kind: {id} args: {args:?}");
            // Detect receive if sign of mult is negative, because
            // sp1_core_machine::autoprecompiles::interaction_builder::InteractionBuilder negates
            // multiplicity for receives.
            // TODO: is this robust? Is it possible that the
            // multiplicity is negative to start with and then get negated again and become
            // positive?
            let (is_receive, mult) = match mult {
                // If a multiplicity is a non-zero polynomial, powdr optimization multiplies
                // `is_valid` to its left. Here we strip off the sign of the
                // multiplicity if it's a receive (negative).
                AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                    op: AlgebraicBinaryOperator::Mul,
                    left,
                    right,
                }) => {
                    match (&**left, &**right) {
                        // Box dereference
                        (
                            AlgebraicExpression::Reference(AlgebraicReference { .. }),
                            AlgebraicExpression::UnaryOperation(AlgebraicUnaryOperation {
                                op: AlgebraicUnaryOperator::Minus,
                                expr: mult,
                            }),
                        ) => (
                            true,
                            &AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                                op: AlgebraicBinaryOperator::Mul,
                                left: left.clone(),
                                right: mult.clone(),
                            }),
                        ),
                        _ => (false, mult),
                    }
                }
                _ => (false, mult),
            };
            // println!("is_receive: {is_receive} mult: {mult}");

            let mult = witness_evaluator.eval_expr(mult);
            let args = args.iter().map(|arg| witness_evaluator.eval_expr(arg)).collect_vec();

            // All instruction AIRs only use the four buses below.
            let interaction_kind = match id {
                1 => InteractionKind::Memory,
                2 => InteractionKind::Program,
                5 => InteractionKind::Byte,
                7 => InteractionKind::State,
                _ => unreachable!("Unexpected bus ID: {id}"),
            };

            let air_interaction = AirInteraction::new(args, mult, interaction_kind);

            // We only support local interaction scope.
            if is_receive {
                // println!("Receiving interaction: {air_interaction:?}");
                builder.receive(air_interaction, InteractionScope::Local);
            } else {
                // println!("Sending interaction: {air_interaction:?}");
                builder.send(air_interaction, InteractionScope::Local);
            }
        }

        // // Add a dummy bus interaction, otherwise `/stark/src/logup_gkr/execution.rs:237:30`
        // fails let col = main.row_slice(0);
        // let col: &AB::Var = col[0].borrow();
        // builder.send_byte(*col, *col, *col, *col, *col);
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
