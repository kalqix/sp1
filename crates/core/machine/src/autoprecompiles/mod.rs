pub mod adapter;
pub mod air_to_symbolic_machine;
pub mod bus_interaction_handler;
pub mod bus_map;
pub mod candidate;
pub mod instruction;
pub mod instruction_machine_handler;
pub mod program;

#[cfg(test)]
mod tests {
    use powdr_autoprecompiles::{build, BasicBlock, DegreeBound, VmConfig};
    use sp1_core_executor::{Instruction, Opcode};

    use crate::{
        autoprecompiles::{
            adapter::Sp1ApcAdapter, bus_interaction_handler::Sp1BusInteractionHandler,
            bus_map::sp1_bus_map, instruction_machine_handler::Sp1InstructionMachineHandler,
        },
        utils::setup_logger,
    };

    fn compile(basic_block: Vec<Instruction>) -> String {
        let vm_config = VmConfig {
            instruction_machine_handler: &Sp1InstructionMachineHandler::new(),
            bus_interaction_handler: Sp1BusInteractionHandler::default(),
            bus_map: sp1_bus_map(),
        };
        // TODO: Is this correct?
        let degree_bound = DegreeBound { identities: 3, bus_interactions: 2 };
        let block = BasicBlock {
            start_idx: 0,
            statements: basic_block.into_iter().map(Into::into).collect(),
        };

        let apc = build::<Sp1ApcAdapter>(block, vm_config, degree_bound, 1234, None).unwrap();
        apc.machine.render(&sp1_bus_map())
    }

    #[test]
    #[should_panic]
    fn test_add() {
        setup_logger();
        let basic_block = vec![Instruction::new(Opcode::ADDI, 29, 0, 5, false, true)];
        let rendered = compile(basic_block);
        tracing::info!("{rendered}");
    }
}
