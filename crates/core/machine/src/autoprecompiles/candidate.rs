use std::{collections::HashMap, path::Path};

use crate::autoprecompiles::{adapter::Sp1ApcAdapter, instruction::Sp1Instruction};
use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc, AdapterApcWithStats, AdapterVmConfig, ApcWithStats},
    blocks::BasicBlock,
    evaluation::{AirStats, EvaluationResult},
    pgo::{ApcCandidateJsonExport, Candidate, KnapsackItem},
};

use serde::{Deserialize, Serialize};

/// A candidate for the SP1 autoprecompiles.
/// Currently does not use pgo data and instead is ranked by the start index of the block.
pub struct Sp1Candidate<A: Adapter> {
    apc: AdapterApc<A>,
    execution_frequency: usize,
    stats: EvaluationResult,
}

impl<A: Adapter> KnapsackItem for Sp1Candidate<A> {
    fn cost(&self) -> usize {
        // TODO: Figure out a better cost model & take #constraints and #bus_interactions into
        // account too.
        self.stats.after.main_columns
    }

    fn value(&self) -> usize {
        // TODO: Figure out a better cost model & take #constraints and #bus_interactions into
        // account too.
        let cells_saved_per_row = self.stats.before.main_columns - self.stats.after.main_columns;

        let value = self.execution_frequency.checked_mul(cells_saved_per_row).unwrap();

        // We need `value()` to be much larger than `cost()` to avoid ties when ranking by `value()
        // / cost()` Therefore, we scale it up by a constant factor.
        value.checked_mul(1000).unwrap()
    }

    fn tie_breaker(&self) -> usize {
        self.apc.block.start_pc.try_into().unwrap()
    }
}

impl Candidate<Sp1ApcAdapter> for Sp1Candidate<Sp1ApcAdapter> {
    fn create(
        apc: AdapterApc<Sp1ApcAdapter>,
        pgo_program_pc_count: &HashMap<u64, u32>,
        vm_config: AdapterVmConfig<Sp1ApcAdapter>,
        _max_degree: usize,
    ) -> Self {
        let stats_before = apc
            .block
            .statements
            .iter()
            .map(|s| *vm_config.instruction_handler.get_instruction_air_stats(s).unwrap())
            .sum();
        let stats_after = AirStats::new(apc.machine());

        let stats = EvaluationResult { before: stats_before, after: stats_after };

        let execution_frequency =
            *pgo_program_pc_count.get(&apc.block.start_pc).unwrap_or(&0) as usize;

        Sp1Candidate { apc, execution_frequency, stats }
    }

    fn to_json_export(&self, apc_candidates_dir_path: &Path) -> ApcCandidateJsonExport {
        ApcCandidateJsonExport {
            execution_frequency: self.execution_frequency,
            original_block: BasicBlock {
                start_pc: self.apc.block.start_pc,
                statements: self
                    .apc
                    .block
                    .statements
                    .iter()
                    .map(|instr| instr.to_string())
                    .collect(),
            },
            stats: self.stats,
            apc_candidate_file: apc_candidates_dir_path
                .join(format!("apc_{}.cbor", self.apc.start_pc()))
                .display()
                .to_string(),
            width_before: self.stats.before.main_columns,
            value: self.value(),
            cost_before: self.stats.before.main_columns as f64,
            cost_after: self.stats.after.main_columns as f64,
        }
    }

    fn into_apc_and_stats(self) -> AdapterApcWithStats<Sp1ApcAdapter> {
        ApcWithStats::from(self.apc).with_stats(self.stats)
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
