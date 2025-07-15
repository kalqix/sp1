use std::collections::HashMap;

use itertools::Itertools;
use powdr_autoprecompiles::{InstructionMachineHandler, SymbolicMachine};
use powdr_expression::AlgebraicExpression;
use powdr_number::FieldElement;
use sp1_stark::InteractionKind;

/// The index of the opcode expression in the PC lookup.
const OPCODE_INDEX: usize = 3;

#[derive(Default)]
pub struct InstructionAirs<P> {
    /// The original AIRs & their name, indexed by their opcode.
    opcode_to_air: HashMap<usize, (SymbolicMachine<P>, String)>,
}

impl<P: FieldElement> InstructionAirs<P> {
    pub fn try_add(&mut self, air: SymbolicMachine<P>, name: String) {
        let pc_lookup = air
            .bus_interactions
            .iter()
            .filter(|bus_interaction| bus_interaction.id == InteractionKind::Program as u64)
            .exactly_one();
        match pc_lookup {
            Err(mut exactly_one_error) => {
                assert!(exactly_one_error.next().is_none(), "Multiple PC lookups!");
                // This AIR does not have a PC lookup, so it's not an instruction AIR and is
                // ignored.
            }
            Ok(pc_lookup) => {
                let opcode = &pc_lookup.args[OPCODE_INDEX];
                if let AlgebraicExpression::Number(opcode_value) = opcode {
                    let opcode = opcode_value.to_degree() as usize;
                    assert!(
                        self.opcode_to_air.insert(opcode, (air, name)).is_none(),
                        "Opcode {opcode} already exists in the instruction AIRs."
                    );
                } else {
                    tracing::warn!(
                        "Skipping Instruction AIR {name}, because the opcode is a complex expression: {opcode}"
                    );
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.opcode_to_air.len()
    }

    pub fn is_empty(&self) -> bool {
        self.opcode_to_air.is_empty()
    }
}

impl<P: FieldElement> InstructionMachineHandler<P> for InstructionAirs<P> {
    fn get_instruction_air(&self, opcode: usize) -> Option<&SymbolicMachine<P>> {
        self.opcode_to_air.get(&opcode).map(|(machine, _)| machine)
    }
}
