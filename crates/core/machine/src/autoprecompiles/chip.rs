use std::{borrow::Borrow, collections::BTreeMap};

use num::pow;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_core_executor::{events::ApcEvent, ExecutionRecord, Instruction, Opcode, Program};
use sp1_stark::{
    air::{MachineAir, SP1AirBuilder},
    Machine,
};
use powdr_autoprecompiles::SymbolicMachine;

use crate::{
    autoprecompiles::instruction_handler::{try_instruction_type_to_air_id, InstructionType},
    riscv::RiscvAir,
    utils::pad_rows_fixed,
};

pub struct ApcChip<const APC_ID: u64, F: PrimeField32> {
    /// Original instructions in the basic block
    original_instructions: Vec<Instruction>,
    /// The columns in arbitrary order
    columns: Vec<AlgebraicReference>,
    /// The mapping from poly_id id to the index in the list of columns.
    /// The values are always unique and contiguous
    column_index_by_poly_id: BTreeMap<u64, usize>,
    apc_machine: powdr_autoprecompiles::SymbolicMachine<F>,
    /// A machine to generate traces for the APC.
    machine: Machine<F, RiscvAir<F>>,
}

impl<const APC_ID: u64, F: PrimeField32> Default for ApcChip<APC_ID, F> {
    fn default() -> Self {
        Self { 
            original_instructions: Vec::new(),
            columns: Vec::new(),
            column_index_by_poly_id: BTreeMap::new(),
            apc_machine: SymbolicMachine { constraints: Vec::new(), bus_interactions: Vec::new() },
            machine: RiscvAir::machine_without_apc()
        }
    }
}

impl<const APC_ID: u64, F: PrimeField32> ApcChip<APC_ID, F> {
    pub fn new(apc_machine: powdr_autoprecompiles::SymbolicMachine<F>, original_instructions: Vec<Instruction>) -> Self {
        let (column_index_by_poly_id, columns): (BTreeMap<_, _>, Vec<_>) = apc_machine
            .main_columns()
            .enumerate()
            .map(|(index, c)| ((c.id, index), c.clone()))
            .unzip();

        let machine = RiscvAir::machine();

        Self {
            columns,
            column_index_by_poly_id,
            apc_machine,
            original_instructions,
            machine,
        }
    }
}

impl<const APC_ID: u64, F: PrimeField32> ApcChip<APC_ID, F> {
    fn event_to_row(&self, _: &ApcEvent, row: &mut [F]) {
        row[0] = F::one();
    }
}

impl<const APC_ID: u64, F: PrimeField32> BaseAir<F> for ApcChip<APC_ID, F> {
    fn width(&self) -> usize {
        self.columns.len()
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
        let ncols = self.width();
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

                let mut row = [F::zero(); ncols];

                // // Go through the original instructions of the APC and map the relevant rows to the APC row
                // // TODO: set this based on the APC
                // let original_instructions = vec![
                //     Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
                //     Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
                // ];
                let mut offset = 0;
                for original_instruction in &self.original_instructions {
                    // Get the air ID for the instruction
                    let air_id = try_instruction_type_to_air_id(InstructionType::from(*original_instruction))
                        .expect("Invalid instruction as an original instruction in an APC: {original_instruction:?}");
                    println!("Processing air_id: {air_id:?}");
                    // Get the next row for this air ID
                    let original_row = iterators
                        .get_mut(&air_id)
                        .and_then(|iter| iter.next())
                        .unwrap_or_else(|| {
                            panic!("No row found for air ID: {air_id:?}");
                        });
                    let len = original_row.len();
                    println!("Original row: {original_row:?}");
                    // Map the row to the APC row. TODO: use the mapping returned by apc generation
                    for (i, value) in original_row.enumerate() {
                        row[i + offset] = value;
                    }
                    offset += len;
                }

                println!("Final row: {row:?}");

                self.event_to_row(event, &mut row);
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || [F::zero(); ncols],
            input.fixed_log2_rows::<F, _>(self),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), ncols)
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
