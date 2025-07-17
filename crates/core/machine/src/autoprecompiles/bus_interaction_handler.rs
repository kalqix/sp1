use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::{BabyBearField, FieldElement};

#[derive(Clone, Default)]
pub struct Sp1BusInteractionHandler;

impl IsBusStateful<BabyBearField> for Sp1BusInteractionHandler {
    fn is_stateful(&self, bus_id: BabyBearField) -> bool {
        // There are 15 buses, see: crates/stark/src/lookup/interaction.rs
        match bus_id.to_degree() {
            1 => true,  // Memory
            2 => false, // Program
            3 => todo!(),
            4 => todo!(),
            5 => false, // Byte
            6 => false, // Range
            7 => true,  // State
            8 => todo!(),
            9 => todo!(),
            10 => todo!(),
            11 => todo!(),
            12 => todo!(),
            13 => todo!(),
            14 => todo!(),
            15 => todo!(),
            _ => unreachable!(),
        }
    }
}

impl BusInteractionHandler<BabyBearField> for Sp1BusInteractionHandler {
    fn handle_bus_interaction(
        &self,
        bus_interaction: BusInteraction<RangeConstraint<BabyBearField>>,
    ) -> BusInteraction<RangeConstraint<BabyBearField>> {
        // TODO: Refine bus interaction handler
        bus_interaction
    }
}
