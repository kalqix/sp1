use std::borrow::Borrow;

use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::air::{MachineAir, SP1AirBuilder};

/// The width of the dummy air, used when no APC is present.
const DUMMY_WIDTH: usize = 1;
/// The number of rows in the dummy air, used when no APC is present.
const DUMMY_HEIGHT: usize = 0;

/// A dummy chip to use when no APC is present.
pub struct DummyChip;

impl<F: PrimeField32> BaseAir<F> for DummyChip {
    fn width(&self) -> usize {
        DUMMY_WIDTH
    }
}

impl<F: PrimeField32> MachineAir<F> for DummyChip {
    type Record = ExecutionRecord;
    type Program = Program;

    fn name(&self) -> String {
        "DummyChip".to_string()
    }

    fn num_rows(&self, _: &Self::Record) -> Option<usize> {
        Some(DUMMY_HEIGHT)
    }

    fn generate_trace(&self, _: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        RowMajorMatrix::default(DUMMY_WIDTH, DUMMY_HEIGHT)
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // No dependencies to generate for the dummy chip
    }

    fn included(&self, _: &Self::Record) -> bool {
        false
    }
}

impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for DummyChip
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
