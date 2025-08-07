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
        instruction_handler::{try_instruction_type_to_air_id, InstructionType},
        Sp1ApcAdapter,
    },
    riscv::RiscvAir,
    utils::pad_rows_fixed,
};

pub struct MaybeApcChip<const APC_ID: u64, F: PrimeField32> {
    /// The chip for the APC, if it exists.
    apc_chip: Option<ApcChip<APC_ID, F>>,
}

impl<const APC_ID: u64, F: PrimeField32> BaseAir<F> for MaybeApcChip<APC_ID, F> {
    fn width(&self) -> usize {
        match &self.apc_chip {
            Some(chip) => chip.width(),
            None => 1, // Default width if no APC chip is present
        }
    }
}

impl<const APC_ID: u64, F: PrimeField32> MaybeApcChip<APC_ID, F> {
    pub fn new(apc: Option<Arc<AdapterApc<Sp1ApcAdapter>>>) -> Self {
        Self { apc_chip: apc.map(|apc| ApcChip::<APC_ID, F>::new(apc)) }
    }
}

impl<const APC_ID: u64, F: PrimeField32> MachineAir<F> for MaybeApcChip<APC_ID, F> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "MaybeApc".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        self.apc_chip.as_ref().and_then(|chip| chip.num_rows(input))
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> slop_matrix::dense::RowMajorMatrix<F> {
        self.apc_chip.as_ref().map_or_else(
            || RowMajorMatrix::new(vec![], 0),
            |chip| chip.generate_trace(input, output),
        )
    }

    fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
        if let Some(chip) = &self.apc_chip {
            chip.generate_dependencies(input, output);
        }
    }

    fn included(&self, shard: &Self::Record) -> bool {
        self.apc_chip.as_ref().is_some_and(|chip| chip.included(shard))
    }
}

impl<const APC_ID: u64, AB: SP1AirBuilder + PairBuilder> Air<AB> for MaybeApcChip<APC_ID, AB::F>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        if let Some(chip) = &self.apc_chip {
            chip.eval(builder);
        } else {
            // If there is no APC chip, we can just assert a dummy condition
            let main = builder.main();
            let col = main.row_slice(0);
            let col: &AB::Var = col[0].borrow();
            builder.assert_bool(*col);
            // Add a dummy bus interaction, otherwise `/stark/src/logup_gkr/execution.rs:237:30`
            // fails
            builder.send_byte(*col, *col, *col, *col, *col);
        }
    }
}

pub struct ApcChip<const APC_ID: u64, F: PrimeField32> {
    apc: Arc<AdapterApc<Sp1ApcAdapter>>,
    /// A machine to generate traces for the APC.
    machine: Machine<F, RiscvAir<F>>,
}

impl<const APC_ID: u64, F: PrimeField32> ApcChip<APC_ID, F> {
    pub fn new(apc: Arc<AdapterApc<Sp1ApcAdapter>>) -> Self {
        Self { apc, machine: RiscvAir::machine_without_apcs() }
    }
}

impl<const APC_ID: u64, F: PrimeField32> BaseAir<F> for ApcChip<APC_ID, F> {
    fn width(&self) -> usize {
        self.apc.machine.main_columns().count()
    }
}

impl<const APC_ID: u64, F: PrimeField32> MachineAir<F> for ApcChip<APC_ID, F> {
    // this may have to be changed
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Apc".to_string()
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        Some(input.get_apc_events(APC_ID).len())
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> slop_matrix::dense::RowMajorMatrix<F> {
        // Get all events for the given APC ID
        let events = input.get_apc_events(APC_ID);
        // Turn each event into a row
        // TODO: can we do this for all records at the same time?
        let mut rows = events
            .par_iter()
            .map(|event| {
                assert!(event.id == APC_ID, "APC ID mismatch");
                let airs = self.machine.chips().to_vec();

                let chips_and_traces = airs
                    .into_par_iter()
                    .filter(|air| air.included(&event.record))
                    .map(|air| {
                        let trace = air.generate_trace(&event.record, &mut Default::default());
                        (air, trace)
                    })
                    .collect::<BTreeMap<_, _>>();

                // create chunked iterators to iterate over the rows of the traces
                let mut iterators = chips_and_traces
                    .iter()
                    .map(|(chip, trace)| (chip.air.id(), trace.rows()))
                    .collect::<BTreeMap<_, _>>();

                let mut row = vec![F::zero(); self.width()];

                // Go through the original instructions of the APC and map the relevant rows to the APC row
                let original_instructions = self.apc.block.statements.iter().map(|instr| instr.0);

                // mapping from poly_id to contiguous index in apc
                let apc_poly_id_to_index = self.apc
                    .machine
                    .main_columns()
                    .enumerate()
                    .map(|(index, c)| (c.id, index))
                    .collect::<BTreeMap<_, _>>();

                for (original_instruction, sub) in original_instructions.zip_eq(self.apc.subs.iter()) {
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
        // APC dependencies are not implemented yet.
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.apc_events.is_empty()
        }
    }
}

impl<const APC_ID: u64, AB: SP1AirBuilder + PairBuilder> Air<AB> for ApcChip<APC_ID, AB::F>
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
