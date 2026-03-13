use crate::autoprecompiles::{adapter::Sp1ApcAdapter, instruction::Sp1Instruction};
use powdr_autoprecompiles::{
    adapter::AdapterApcWithStats, blocks::BasicBlock, evaluation::EvaluationResult,
    pgo::ApcCandidate,
};

use serde::{Deserialize, Serialize};

/// A candidate for the SP1 autoprecompiles.
/// Currently does not use pgo data and instead is ranked by the start index of the block.
pub struct Sp1Candidate {
    apc_with_stats: AdapterApcWithStats<Sp1ApcAdapter>,
    execution_frequency: usize,
}

impl ApcCandidate<Sp1ApcAdapter> for Sp1Candidate {
    fn create(apc_with_stats: AdapterApcWithStats<Sp1ApcAdapter>) -> Self {
        Self { apc_with_stats, execution_frequency: 0 }
    }

    fn inner(&self) -> &AdapterApcWithStats<Sp1ApcAdapter> {
        &self.apc_with_stats
    }

    fn into_inner(self) -> AdapterApcWithStats<Sp1ApcAdapter> {
        self.apc_with_stats
    }

    fn cost_before_opt(&self) -> usize {
        self.apc_with_stats.evaluation_result().before.main_columns
    }

    fn cost_after_opt(&self) -> usize {
        self.apc_with_stats.evaluation_result().after.main_columns
    }

    fn value_per_use(&self) -> usize {
        // TODO: Figure out a better cost model & take #constraints and #bus_interactions into
        // account too.
        let cells_saved_per_row = self.apc_with_stats.evaluation_result().before.main_columns
            - self.apc_with_stats.evaluation_result().after.main_columns;

        let value = self.execution_frequency.checked_mul(cells_saved_per_row).unwrap();

        // We need `value()` to be much larger than `cost()` to avoid ties when ranking by `value()
        // / cost()` Therefore, we scale it up by a constant factor.
        value.checked_mul(1000).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Sp1ApcCandidateJsonExport {
    // start_pc
    start_pc: u64,
    // execution_frequency
    execution_frequency: usize,
    // original instructions
    original_block: BasicBlock<Sp1Instruction>,
    // before and after optimization stats
    stats: EvaluationResult,
    // path to the apc candidate file
    apc_candidate_file: String,
}
