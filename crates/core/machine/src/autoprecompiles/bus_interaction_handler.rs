use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::BabyBearField;

#[derive(Clone, Default)]
pub struct Sp1BusInteractionHandler;

impl IsBusStateful<BabyBearField> for Sp1BusInteractionHandler {
    fn is_stateful(&self, _bus_id: BabyBearField) -> bool {
        todo!()
    }
}

impl BusInteractionHandler<BabyBearField> for Sp1BusInteractionHandler {
    fn handle_bus_interaction(
        &self,
        _bus_interaction: BusInteraction<RangeConstraint<BabyBearField>>,
    ) -> BusInteraction<RangeConstraint<BabyBearField>> {
        todo!()
    }
}
