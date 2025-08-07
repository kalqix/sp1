use std::borrow::Borrow;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{events::ApcEvent, ExecutionRecord, Program};
use sp1_stark::air::{MachineAir, SP1AirBuilder};

use crate::utils::pad_rows_fixed;

#[derive(Default)]
pub struct ApcChip<const APC_ID: u64, F: PrimeField32> {
    _marker: std::marker::PhantomData<F>,
}

impl<const APC_ID: u64, F: PrimeField32> ApcChip<APC_ID, F> {
    fn event_to_row(&self, _: &ApcEvent, row: &mut [F; 1]) {
        row[0] = F::one();
    }
}

const NUM_APC_COLS: usize = 1; // TODO: Adjust this based on the actual number of columns needed for APC

impl<const APC_ID: u64, F: PrimeField32> BaseAir<F> for ApcChip<APC_ID, F> {
    fn width(&self) -> usize {
        NUM_APC_COLS
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
        let mut rows = events
            .par_iter()
            .map(|event| {
                assert!(event.id == APC_ID, "APC ID mismatch");
                let mut row = [F::zero(); NUM_APC_COLS];
                self.event_to_row(event, &mut row);
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || [F::zero(); NUM_APC_COLS],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_APC_COLS)
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
