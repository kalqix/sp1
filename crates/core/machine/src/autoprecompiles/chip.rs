use std::borrow::Borrow;

use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Chip,
};

use crate::{riscv::RiscvAir, utils::zeroed_f_vec};

// TODO: There can only be one APC right now

#[derive(Default)]
pub struct ApcChip<F: PrimeField32> {
    dummy_chips: Vec<Chip<F, RiscvAir<F>>>,
}

impl<F: PrimeField32> ApcChip<F> {
    pub(crate) fn with_chips_and_costs(chips_without_apc: Vec<Chip<F, RiscvAir<F>>>) -> Self {
        Self { dummy_chips: chips_without_apc }
    }
}

const NUM_APC_COLS: usize = 1; // TODO: Adjust this based on the actual number of columns needed for APC

impl<F: PrimeField32> BaseAir<F> for ApcChip<F> {
    fn width(&self) -> usize {
        NUM_APC_COLS
    }
}

impl<F: PrimeField32> MachineAir<F> for ApcChip<F> {
    // this may have to be changed
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Apc".to_string()
    }

    fn generate_trace(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> slop_matrix::dense::RowMajorMatrix<F> {
        let nb_rows = input.apc_events.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = <ApcChip<F> as MachineAir<F>>::num_rows(self, input).unwrap();
        let values = zeroed_f_vec(padded_nb_rows * NUM_APC_COLS);
        for event in &input.apc_events {
            println!("Processing APC event: {event:#?}");

            // TODO: this could be done in parallel
            for dummy_chip in &self.dummy_chips {
                let matrix = dummy_chip.generate_trace(&event.record, &mut Default::default());
                println!("Matrix for dummy chip {} {matrix:?}", dummy_chip.name());
                // why is it doing all this random stuff i don't understand
            }
        }

        RowMajorMatrix::new(values, NUM_APC_COLS)
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
    }
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::{Instruction, Opcode};

    use crate::{io::SP1Stdin, utils};

    use super::*;

    #[tokio::test]
    async fn test_apc() {
        utils::setup_logger();
        // main:
        //     block_42424242
        //      addi x29, x0, 5
        //      addi x30, x0, 37
        //     add x31, x30, x29

        // TODO: rely on elf instead
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];

        let program = Program::new(instructions, 0, 0);
        let program = program.with_apcs(&[(0, 2)]);

        let stdin = SP1Stdin::new();
        crate::utils::run_test(program, stdin).await.unwrap();
    }
}
