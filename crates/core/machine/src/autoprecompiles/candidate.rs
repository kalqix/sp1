use std::{collections::HashMap, path::Path};

use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc, AdapterVmConfig},
    blocks::{Candidate, KnapsackItem},
    evaluation::{AirStats, EvaluationResult},
};

use crate::autoprecompiles::adapter::Sp1ApcAdapter;

/// A candidate for the SP1 autoprecompiles.
/// Currently does not use pgo data and instead is ranked by the start index of the block.
pub struct Sp1Candidate<A: Adapter> {
    apc: AdapterApc<A>,
    execution_frequency: usize,
    stats: EvaluationResult,
}

impl<A: Adapter> KnapsackItem for Sp1Candidate<A> {
    fn cost(&self) -> usize {
        self.stats.after.main_columns
    }

    fn value(&self) -> usize {
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
    type JsonExport = ();
    type ApcStats = EvaluationResult;

    fn create(
        apc: AdapterApc<Sp1ApcAdapter>,
        pgo_program_pc_count: &HashMap<u64, u32>,
        vm_config: AdapterVmConfig<Sp1ApcAdapter>,
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

    fn to_json_export(&self, _apc_candidates_dir_path: &Path) -> Self::JsonExport {}

    fn into_apc_and_stats(self) -> (AdapterApc<Sp1ApcAdapter>, Self::ApcStats) {
        (self.apc, self.stats)
    }
}
