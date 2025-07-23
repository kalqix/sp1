use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::{BabyBearField, FieldElement};
use sp1_stark::InteractionKind;

#[derive(Clone, Default)]
pub struct Sp1BusInteractionHandler;

impl IsBusStateful<BabyBearField> for Sp1BusInteractionHandler {
    fn is_stateful(&self, bus_id: BabyBearField) -> bool {
        let kind = InteractionKind::all_kinds()
            .into_iter()
            .find(|kind| *kind as u64 == bus_id.to_degree())
            .unwrap();

        match kind {
            InteractionKind::Memory => true,
            InteractionKind::Program => false,
            InteractionKind::Byte => false,
            InteractionKind::State => true,
            // All instruction AIRs only use the four buses above.
            _ => unreachable!("Unexpected bus: {:?}", kind),
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
