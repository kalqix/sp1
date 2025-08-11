use std::{borrow::Borrow, collections::BTreeMap, sync::Arc};

use itertools::Itertools;
use powdr_autoprecompiles::adapter::AdapterApc;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Machine,
};

use crate::{
    autoprecompiles::{
        adapter::Sp1ApcAdapter,
        instruction_handler::{try_instruction_type_to_air_id, InstructionType},
    },
    riscv::RiscvAir,
    utils::pad_rows_fixed,
};

#[derive(Debug)]
struct CachedApc {
    /// The APC
    apc: Arc<AdapterApc<Sp1ApcAdapter>>,
    /// The cached width of the APC.
    width: usize,
}

impl From<Arc<AdapterApc<Sp1ApcAdapter>>> for CachedApc {
    fn from(apc: Arc<AdapterApc<Sp1ApcAdapter>>) -> Self {
        let width = apc.machine.main_columns().count();
        Self { apc, width }
    }
}

#[derive(Debug)]
pub struct ApcChip<F: PrimeField32> {
    /// The ID of the APC.
    id: u64,
    /// The cached APC.
    cached_apc: CachedApc,
    /// A machine to generate traces for the APC.
    machine: Machine<F, RiscvAir<F>>,
}

impl<F: PrimeField32> ApcChip<F> {
    pub fn new(apc: Arc<AdapterApc<Sp1ApcAdapter>>, id: usize) -> Self {
        Self { id: id as u64, cached_apc: apc.into(), machine: RiscvAir::machine() }
    }

    pub fn apc(&self) -> &Arc<AdapterApc<Sp1ApcAdapter>> {
        &self.cached_apc.apc
    }

    pub fn id(&self) -> u64 {
        self.id
    }
}

impl<F: PrimeField32> BaseAir<F> for ApcChip<F> {
    fn width(&self) -> usize {
        self.cached_apc.width
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
                    tracing::error!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        });
                    tracing::error!("Original row: {original_row:?}");
                    // Map the row to the APC row. TODO: use the mapping returned by apc generation.
                    for (i, value) in original_row.enumerate() {
                        // get poly_id from sub
                        let poly_id = sub.get(i).expect("Not in dummy");
                        // get index in apc from poly_id
                        if let Some(index) = apc_poly_id_to_index.get(poly_id) {
                            tracing::error!("Setting row[{index}] to {value:?}");
                            row[*index] = value;
                        } else {
                            tracing::error!("Poly ID {poly_id} not found in APC columns (usually due to optimization)");
                        }
                    }
                }

                tracing::error!("Final row: {row:?}");

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

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // TODO: here we should probably only generate the dependencies which were not optimised
        // away in the APC
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.apc_events.is_empty()
        }
    }
}

impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for ApcChip<AB::F>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        // TODO: Implement the evaluation logic for the APC air
        // For now, boolean constrain a single column
        let main = builder.main();
        let col = main.row_slice(0);
        let col: &AB::Var = col[0].borrow();
        builder.assert_bool(*col);
        // Add a dummy bus interaction, otherwise `/stark/src/logup_gkr/execution.rs:237:30` fails
        builder.send_byte(*col, *col, *col, *col, *col);
    }
}
