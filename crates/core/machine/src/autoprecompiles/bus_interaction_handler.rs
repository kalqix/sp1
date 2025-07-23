use sp1_curves::{One, Zero};
use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::{BabyBearField, FieldElement, LargeInt};
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
        let (Some(bus_id), Some(multiplicity)) = (
            bus_interaction.bus_id.try_to_single_value(),
            bus_interaction.multiplicity.try_to_single_value(),
        ) else {
            return bus_interaction;
        };

        if multiplicity.is_zero() {
            return bus_interaction;
        }

        let kind = InteractionKind::all_kinds()
            .into_iter()
            .find(|kind| *kind as u64 == bus_id.to_degree())
            .unwrap();

        let payload_constraints = match kind {
            InteractionKind::Memory => handle_memory(&bus_interaction.payload, multiplicity),
            InteractionKind::Program => bus_interaction.payload,
            InteractionKind::Byte => handle_byte(&bus_interaction.payload),
            InteractionKind::State => bus_interaction.payload,
            _ => unreachable!("Unexpected bus: {:?}", kind),
        };

        BusInteraction {
            payload: payload_constraints,
            ..bus_interaction
        }
    }
}

fn handle_memory(
    payload: &[RangeConstraint<BabyBearField>],
    multiplicity: BabyBearField,
) -> Vec<RangeConstraint<BabyBearField>> {
    // Memory bus fields: (clk_high, clk_low, addr (3 fields), data (4 fields))
    let [clk_high, clk_low, addr1, addr2, addr3, _data1, _data2, _data3, _data4] = payload else {
        panic!("Invalid memory bus payload length");
    };

    // For sends (multiplicity > 0), values are range-checked
    if multiplicity > BabyBearField::zero() {
        // Data values are assumed to be byte-range-checked
        vec![
            clk_high.clone(),
            clk_low.clone(),
            addr1.clone(),
            addr2.clone(),
            addr3.clone(),
            byte_constraint(),
            byte_constraint(),
            byte_constraint(),
            byte_constraint(),
        ]
    } else {
        // For receives, return original constraints
        payload.to_vec()
    }
}

fn handle_byte(payload: &[RangeConstraint<BabyBearField>]) -> Vec<RangeConstraint<BabyBearField>> {
    // Byte bus fields: (opcode, a, b, c)
    let [opcode, a, b, c] = payload else {
        panic!("Invalid byte bus payload length");
    };

    match opcode
        .try_to_single_value()
        .map(|v| v.to_integer().try_into_u64().unwrap())
    {
        // AND: a = b & c
        Some(0) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let result = BabyBearField::from(
                    b_val.to_integer().try_into_u64().unwrap()
                        & c_val.to_integer().try_into_u64().unwrap(),
                );
                vec![
                    RangeConstraint::from_value(BabyBearField::zero()),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    byte_constraint(),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::zero()),
                    byte_constraint(),
                    byte_constraint(),
                    byte_constraint(),
                ]
            }
        }
        // OR: a = b | c
        Some(1) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let result = BabyBearField::from(
                    b_val.to_integer().try_into_u64().unwrap()
                        | c_val.to_integer().try_into_u64().unwrap(),
                );
                vec![
                    RangeConstraint::from_value(BabyBearField::one()),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    byte_constraint(),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::one()),
                    byte_constraint(),
                    byte_constraint(),
                    byte_constraint(),
                ]
            }
        }
        // XOR: a = b ^ c
        Some(2) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let result = BabyBearField::from(
                    b_val.to_integer().try_into_u64().unwrap()
                        ^ c_val.to_integer().try_into_u64().unwrap(),
                );
                vec![
                    RangeConstraint::from_value(BabyBearField::from(2u64)),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    byte_constraint(),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::from(2u64)),
                    byte_constraint(),
                    byte_constraint(),
                    byte_constraint(),
                ]
            }
        }
        // U8Range: assert(a == 0 && b < 256 && c < 256)
        Some(3) => vec![
            RangeConstraint::from_value(BabyBearField::from(3u64)),
            RangeConstraint::from_value(BabyBearField::zero()),
            byte_constraint(),
            byte_constraint(),
        ],
        // LTU: a = b < c
        Some(4) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let result = if b_val.to_integer().try_into_u64().unwrap()
                    < c_val.to_integer().try_into_u64().unwrap()
                {
                    BabyBearField::one()
                } else {
                    BabyBearField::zero()
                };
                vec![
                    RangeConstraint::from_value(BabyBearField::from(4u64)),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    byte_constraint(),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::from(4u64)),
                    RangeConstraint::from_mask(0x1u64),
                    byte_constraint(),
                    byte_constraint(),
                ]
            }
        }
        // MSB: a = b >> 7, c = 0
        Some(5) => {
            if let Some(b_val) = b.try_to_single_value() {
                let result =
                    BabyBearField::from((b_val.to_integer().try_into_u64().unwrap() >> 7) & 1);
                vec![
                    RangeConstraint::from_value(BabyBearField::from(5u64)),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    RangeConstraint::from_value(BabyBearField::zero()),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::from(5u64)),
                    RangeConstraint::from_mask(0x1u64),
                    byte_constraint(),
                    RangeConstraint::from_value(BabyBearField::zero()),
                ]
            }
        }
        // SR: a = b << c
        Some(6) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let shift = c_val.to_integer().try_into_u64().unwrap();
                let result = if shift < 8 {
                    BabyBearField::from(
                        (b_val.to_integer().try_into_u64().unwrap() << shift) & 0xff,
                    )
                } else {
                    BabyBearField::zero()
                };
                vec![
                    RangeConstraint::from_value(BabyBearField::from(6u64)),
                    RangeConstraint::from_value(result),
                    byte_constraint(),
                    byte_constraint(),
                ]
            } else {
                vec![
                    RangeConstraint::from_value(BabyBearField::from(6u64)),
                    byte_constraint(),
                    byte_constraint(),
                    byte_constraint(),
                ]
            }
        }
        // Range: assert(a <= 2**b && c == 0)
        Some(7) => {
            vec![
                RangeConstraint::from_value(BabyBearField::from(7u64)),
                a.clone(),
                b.clone(),
                RangeConstraint::from_value(BabyBearField::zero()),
            ]
        }
        // Unknown opcode
        _ => payload.to_vec(),
    }
}

fn byte_constraint() -> RangeConstraint<BabyBearField> {
    RangeConstraint::from_mask(0xffu64)
}
