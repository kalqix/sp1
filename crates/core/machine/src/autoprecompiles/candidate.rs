use std::{collections::HashMap, path::Path};

use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc, AdapterVmConfig},
    blocks::{Candidate, KnapsackItem},
};

/// A candidate for the SP1 autoprecompiles.
/// Currently does not use pgo data and instead is ranked by the start index of the block.
pub struct Sp1Candidate<A: Adapter> {
    apc: AdapterApc<A>,
}

impl<A: Adapter> KnapsackItem for Sp1Candidate<A> {
    fn cost(&self) -> usize {
        // TODO: use column count to rank candidates
        1
    }

    fn value(&self) -> usize {
        // TODO: use trace cells and pgo data to rank candidates
        1
    }

    fn tie_breaker(&self) -> usize {
        self.apc.block.start_pc.try_into().unwrap()
    }
}

impl<A: Adapter> Candidate<A> for Sp1Candidate<A> {
    type JsonExport = ();
    type ApcStats = ();

    fn create(apc: AdapterApc<A>, _: &HashMap<u64, u32>, _: AdapterVmConfig<A>) -> Self {
        Sp1Candidate { apc }
    }

    fn to_json_export(&self, _apc_candidates_dir_path: &Path) -> Self::JsonExport {}

    fn into_apc_and_stats(self) -> (AdapterApc<A>, Self::ApcStats) {
        (self.apc, ())
    }
}
