use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc},
    blocks::{Candidate, KnapsackItem},
    Apc,
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
        self.apc.block.start_idx
    }
}

impl<A: Adapter> Candidate<A> for Sp1Candidate<A> {
    type JsonExport = ();
    type ApcStats = ();

    fn create(
        apc: Apc<
            <A as powdr_autoprecompiles::adapter::Adapter>::Field,
            <A as powdr_autoprecompiles::adapter::Adapter>::Instruction,
        >,
        _: &std::collections::HashMap<u32, u32>,
        _: powdr_autoprecompiles::VmConfig<
            <A as powdr_autoprecompiles::adapter::Adapter>::InstructionMachineHandler,
            <A as powdr_autoprecompiles::adapter::Adapter>::BusInteractionHandler,
        >,
    ) -> Self {
        Sp1Candidate { apc }
    }

    fn to_json_export(&self, _apc_candidates_dir_path: &std::path::Path) -> Self::JsonExport {}

    fn into_apc_and_stats(
        self,
    ) -> (
        Apc<
            <A as powdr_autoprecompiles::adapter::Adapter>::Field,
            <A as powdr_autoprecompiles::adapter::Adapter>::Instruction,
        >,
        Self::ApcStats,
    ) {
        (self.apc, ())
    }
}
