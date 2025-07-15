use powdr_autoprecompiles::{
    adapter::{Adapter, AdapterApc},
    blocks::{Candidate, KnapsackItem},
    Apc,
};

pub struct Sp1Candidate<A: Adapter> {
    apc: AdapterApc<A>,
}

impl<A: Adapter> KnapsackItem for Sp1Candidate<A> {
    fn cost(&self) -> usize {
        1
    }

    fn value(&self) -> usize {
        todo!()
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
            <A as powdr_autoprecompiles::adapter::Adapter>::PowdrField,
            <A as powdr_autoprecompiles::adapter::Adapter>::Instruction,
        >,
        pgo_program_idx_count: &std::collections::HashMap<u32, u32>,
        vm_config: powdr_autoprecompiles::VmConfig<
            <A as powdr_autoprecompiles::adapter::Adapter>::InstructionMachineHandler,
            <A as powdr_autoprecompiles::adapter::Adapter>::BusInteractionHandler,
        >,
    ) -> Self {
        todo!()
    }

    fn to_json_export(&self, apc_candidates_dir_path: &std::path::Path) -> Self::JsonExport {
        todo!()
    }

    fn into_apc_and_stats(
        self,
    ) -> (
        Apc<
            <A as powdr_autoprecompiles::adapter::Adapter>::PowdrField,
            <A as powdr_autoprecompiles::adapter::Adapter>::Instruction,
        >,
        Self::ApcStats,
    ) {
        todo!()
    }
}
