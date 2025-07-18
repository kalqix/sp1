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
    use std::collections::BTreeSet;

    use powdr_autoprecompiles::{
        blocks::collect_basic_blocks, build, BasicBlock, DegreeBound, VmConfig,
    };
    use slop_baby_bear::BabyBear;
    use sp1_core_executor::{Instruction, Opcode, Program};
    use sp1_build::BuildArgs;

    use crate::{
        autoprecompiles::{
            adapter::Sp1ApcAdapter,
            bus_interaction_handler::Sp1BusInteractionHandler,
            bus_map::sp1_bus_map,
            instruction::Sp1Instruction,
            instruction_machine_handler::{air_id_to_opcodes, Sp1InstructionMachineHandler},
            program::Sp1Program,
        },
        riscv::RiscvAir,
        utils::setup_logger,
    };

    fn detect_basic_blocks(
        program: Program,
        jumpdest: BTreeSet<u64>,
    ) -> Vec<BasicBlock<Sp1Instruction>> {
        // We allow all opcodes
        let opcode_allowlist = RiscvAir::<BabyBear>::airs()
            .into_iter()
            .map(|air| air.id())
            .flat_map(air_id_to_opcodes)
            .map(|opcode| opcode as usize)
            .collect();
        // We define the branch opcodes manually
        let branch_opcodes = [
            Opcode::BEQ,
            Opcode::BNE,
            Opcode::BLT,
            Opcode::BGE,
            Opcode::BLTU,
            Opcode::BGEU,
            Opcode::JAL,
            Opcode::JALR,
        ]
        .into_iter()
        .map(|opcode| opcode as usize)
        .collect();
        collect_basic_blocks::<Sp1ApcAdapter>(
            &Sp1Program(program),
            &jumpdest,
            &opcode_allowlist,
            &branch_opcodes,
        )
    }

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

    #[test]
    #[should_panic = "get labels"]
    fn test_collect_basic_blocks() {
        setup_logger();
        // let instructions = vec![];
        let fibo_path = "../../test-artifacts/programs/fibonacci";
        // let output_directory = "../../test-artifacts/programs/fibonacci".to_string();
        sp1_helper::build_program_with_args(
            fibo_path,
            BuildArgs {
                rustflags: vec!["-C".to_string(), "link-arg=--emit-relocs".to_string()],
                // ... set other fields as needed, or use ..Default::default()
                // output_directory: Some(output_directory),
                ..Default::default()
            },
        );
        // let sp1_elf = test_artifacts::FIBONACCI_ELF;
        let sp1_elf = std::fs::read("../../test-artifacts/programs/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/fibonacci-program-tests").unwrap();
        println!("sp1_elf read successfully");
        
        let powdr_elf = powdr_riscv_elf::load_elf_from_buffer(&sp1_elf);
        let text_labels: BTreeSet<_> = powdr_elf.text_labels().iter().map(|&x| x as u64).collect();
        let program = Program::from(&sp1_elf).unwrap();
        let basic_blocks = detect_basic_blocks(program, text_labels);

        // assert!(basic_blocks.is_empty());
    }
}
