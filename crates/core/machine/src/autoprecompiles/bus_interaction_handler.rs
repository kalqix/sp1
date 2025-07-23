use itertools::repeat_n;
use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::{BabyBearField, FieldElement, LargeInt};
use sp1_core_executor::ByteOpcode;
use sp1_curves::{One, Zero};
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
            // All fields of the PC lookup should be known, so we don't need to refine
            // range constraints here.
            InteractionKind::Program => bus_interaction.payload,
            InteractionKind::Byte => handle_byte(&bus_interaction.payload),
            // The payload is (clk (2 fields), pc (3 fields)). The PC should be known and we can't
            // make any assumptions about the clk values, so we simply return the original range
            // constraints.
            InteractionKind::State => bus_interaction.payload,
            _ => unreachable!("Unexpected bus: {:?}", kind),
        };

        BusInteraction { payload: payload_constraints, ..bus_interaction }
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

    if multiplicity == BabyBearField::one() {
        // When sending, we are getting the previous values.
        let is_x0 = addr1.try_to_single_value() == Some(BabyBearField::zero())
            && addr2.try_to_single_value() == Some(BabyBearField::zero())
            && addr3.try_to_single_value() == Some(BabyBearField::zero());
        let data = if is_x0 {
            // By the assumption that x0 is never written to, we know the result.
            repeat_n(RangeConstraint::from_value(BabyBearField::zero()), 4)
        } else {
            // By the assumption that all data written to registers or memory are range-checked,
            // we can return a 16-Bit range constraint for the data limbs.
            repeat_n(bit16_constraint(), 4)
        };

        [clk_high.clone(), clk_low.clone(), addr1.clone(), addr2.clone(), addr3.clone()]
            .into_iter()
            .chain(data)
            .collect()
    } else {
        // Otherwise, we can't make any assumptions.
        payload.to_vec()
    }
}

fn handle_byte(payload: &[RangeConstraint<BabyBearField>]) -> Vec<RangeConstraint<BabyBearField>> {
    // Byte bus fields: (opcode, a, b, c)
    let [opcode, a, b, c] = payload else {
        panic!("Invalid byte bus payload length");
    };

    // We know that b and c must be bytes:
    let b = b.conjunction(&byte_constraint());
    let c = c.conjunction(&byte_constraint());
    let zero = RangeConstraint::from_value(BabyBearField::zero());

    let opcode_value = opcode.try_to_single_value();
    let byte_opcode = opcode_value.map(|opcode| {
        ByteOpcode::byte_table()
            .into_iter()
            .chain([ByteOpcode::Range])
            .find(|kind| *kind as u64 == opcode.to_degree())
            .unwrap_or_else(|| panic!("Unknown byte opcode: {opcode}"))
    });

    // The range constraint on `a` depends on the opcode.
    let (a, b, c) = match byte_opcode {
        // AND: a = b & c
        Some(ByteOpcode::AND) => {
            if let (Some(b_value), Some(c_value)) =
                (b.try_to_single_value(), c.try_to_single_value())
            {
                let a = BabyBearField::from(b_value.to_degree() & c_value.to_degree());
                (RangeConstraint::from_value(a), b, c)
            } else {
                let a = b.conjunction(&c);
                (a, b, c)
            }
        }
        // OR: a = b | c
        Some(ByteOpcode::OR) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let a = BabyBearField::from(b_val.to_degree() | c_val.to_degree());
                (RangeConstraint::from_value(a), b, c)
            } else {
                // TODO: This a avoids a bug in `RangeConstraint::conjunction`, see:
                // https://github.com/powdr-labs/powdr/pull/3079
                let a_mask = b.mask().try_into_u32().unwrap() | c.mask().try_into_u32().unwrap();
                (RangeConstraint::from_mask(a_mask), b, c)
            }
        }
        // XOR: a = b ^ c
        Some(ByteOpcode::XOR) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let a = BabyBearField::from(b_val.to_degree() ^ c_val.to_degree());
                (RangeConstraint::from_value(a), b, c)
            } else {
                // TODO: This a avoids a bug in `RangeConstraint::conjunction`, see:
                // https://github.com/powdr-labs/powdr/pull/3079
                let a_mask = b.mask().try_into_u32().unwrap() | c.mask().try_into_u32().unwrap();
                (RangeConstraint::from_mask(a_mask), b, c)
            }
        }
        // U8Range: assert(a == 0 && b < 256 && c < 256)
        Some(ByteOpcode::U8Range) => (
            RangeConstraint::from_value(BabyBearField::zero()),
            byte_constraint(),
            byte_constraint(),
        ),
        // LTU: a = b < c
        Some(ByteOpcode::LTU) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                // We know both values, so we can compute the result directly.
                let result = if b_val.to_degree() < c_val.to_degree() {
                    BabyBearField::one()
                } else {
                    BabyBearField::zero()
                };
                (RangeConstraint::from_value(result), b, c)
            } else {
                (RangeConstraint::from_mask(0x1u64), b, c)
            }
        }
        // MSB: a = b >> 7, c = 0
        Some(ByteOpcode::MSB) => {
            if let Some(b_val) = b.try_to_single_value() {
                assert!(b_val.to_degree() < 256);
                let result = BabyBearField::from((b_val.to_degree() >> 7) & 1);
                (RangeConstraint::from_value(result), b, zero)
            } else {
                (RangeConstraint::from_mask(0x1u64), b, zero)
            }
        }
        // SR: a = b >> c
        Some(ByteOpcode::SR) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let shift = c_val.to_degree();
                let result = if shift < 8 {
                    BabyBearField::from((b_val.to_degree() >> shift) & 0xff)
                } else {
                    BabyBearField::zero()
                };
                (RangeConstraint::from_value(result), b, c)
            } else {
                (byte_constraint(), b, c)
            }
        }
        // Range: assert(a <= 2**b && c == 0)
        Some(ByteOpcode::Range) => {
            let b = b.conjunction(&RangeConstraint::from_range(
                BabyBearField::zero(),
                BabyBearField::from(16),
            ));
            let max_bit = if let Some(b_val) = b.try_to_single_value() {
                assert!(b_val.to_degree() <= 16);
                b_val.to_degree()
            } else {
                b.range().1.to_degree()
            };
            let a = a.conjunction(&RangeConstraint::from_mask((1u64 << max_bit) - 1));
            (a, b, zero)
        }
        None => {
            // The opcode is unknown, but the largest value `a` can have is 0xffff
            // (if opcode = 7 and b = 16).
            let a = a.conjunction(&bit16_constraint());
            (a, b, c)
        }
    };
    vec![opcode.clone(), a, b, c]
}

fn byte_constraint() -> RangeConstraint<BabyBearField> {
    RangeConstraint::from_mask(0xffu64)
}

fn bit16_constraint() -> RangeConstraint<BabyBearField> {
    RangeConstraint::from_mask(0xffffu64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use powdr_constraint_solver::constraint_system::{BusInteraction, BusInteractionHandler};

    fn run(
        interaction_kind: InteractionKind,
        payload: Vec<RangeConstraint<BabyBearField>>,
        multiplicity: BabyBearField,
    ) -> Vec<RangeConstraint<BabyBearField>> {
        let handler = Sp1BusInteractionHandler;

        let bus_interaction = BusInteraction {
            bus_id: RangeConstraint::from_value(BabyBearField::from(interaction_kind as u64)),
            multiplicity: RangeConstraint::from_value(multiplicity),
            payload,
        };
        let result = handler.handle_bus_interaction(bus_interaction);
        result.payload
    }

    pub fn value(value: u64) -> RangeConstraint<BabyBearField> {
        RangeConstraint::from_value(BabyBearField::from(value))
    }

    pub fn mask(mask: u64) -> RangeConstraint<BabyBearField> {
        RangeConstraint::from_mask(mask)
    }

    pub fn default() -> RangeConstraint<BabyBearField> {
        RangeConstraint::default()
    }

    #[test]
    fn test_memory_send() {
        let clk_high = default();
        let clk_low = default();
        let addr1 = default();
        let addr2 = default();
        let addr3 = default();
        let data = vec![default(), default(), default(), default()];

        let result = run(
            InteractionKind::Memory,
            [&clk_high, &clk_low, &addr1, &addr2, &addr3]
                .into_iter()
                .cloned()
                .chain(data)
                .collect(),
            BabyBearField::one(),
        );

        assert_eq!(result.len(), 9);
        // clk and addr fields should be unchanged
        assert_eq!(result[0], clk_high);
        assert_eq!(result[1], clk_low);
        assert_eq!(result[2], addr1);
        assert_eq!(result[3], addr2);
        assert_eq!(result[4], addr3);
        // Data fields should be 16-bit constrained
        assert_eq!(result[5], bit16_constraint());
        assert_eq!(result[6], bit16_constraint());
        assert_eq!(result[7], bit16_constraint());
        assert_eq!(result[8], bit16_constraint());
    }

    #[test]
    fn test_memory_receive() {
        let clk_high = value(100);
        let clk_low = value(200);
        let addr1 = value(0x1234);
        let addr2 = value(0x5678);
        let addr3 = value(0x9ABC);
        let data = vec![default(), default(), default(), default()];

        let result = run(
            InteractionKind::Memory,
            [&clk_high, &clk_low, &addr1, &addr2, &addr3]
                .into_iter()
                .cloned()
                .chain(data)
                .collect(),
            BabyBearField::from(-1),
        );

        // For receives, original constraints should be returned unchanged
        assert_eq!(result.len(), 9);
        assert_eq!(result[0], clk_high);
        assert_eq!(result[1], clk_low);
        assert_eq!(result[2], addr1);
        assert_eq!(result[3], addr2);
        assert_eq!(result[4], addr3);
        assert_eq!(result[5], default());
        assert_eq!(result[6], default());
        assert_eq!(result[7], default());
        assert_eq!(result[8], default());
    }

    #[test]
    fn test_byte_and_known() {
        let opcode = value(0); // AND opcode
        let a = default();
        let b = value(0b10101010);
        let c = value(0b11001100);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(0));
        assert_eq!(result[1], value(0b10001000)); // a = b & c
        assert_eq!(result[2], value(0b10101010));
        assert_eq!(result[3], value(0b11001100));
    }

    #[test]
    fn test_byte_and_unknown() {
        let opcode = value(0); // AND opcode
        let a = default();
        let b = default();
        let c = mask(0xf);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(0));
        assert_eq!(result[1], mask(0xf));
        assert_eq!(result[2], mask(0xff));
        assert_eq!(result[3], mask(0xf));
    }

    #[test]
    fn test_byte_or_known() {
        let opcode = value(1); // OR opcode
        let a = default();
        let b = value(0b10101010);
        let c = value(0b11001100);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(1));
        assert_eq!(result[1], value(0b11101110)); // a = b | c
        assert_eq!(result[2], value(0b10101010));
        assert_eq!(result[3], value(0b11001100));
    }

    #[test]
    fn test_byte_or_unknown() {
        let opcode = value(1); // OR opcode
        let a = default();
        let b = mask(0xf0);
        let c = mask(0x01);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(1));
        assert_eq!(result[1], mask(0xf1));
        assert_eq!(result[2], mask(0xf0));
        assert_eq!(result[3], mask(0x01));
    }

    #[test]
    fn test_byte_xor_known() {
        let opcode = value(2); // XOR opcode
        let a = default();
        let b = value(0b10101010);
        let c = value(0b11001100);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(2));
        assert_eq!(result[1], value(0b01100110)); // a = b ^ c
        assert_eq!(result[2], value(0b10101010));
        assert_eq!(result[3], value(0b11001100));
    }

    #[test]
    fn test_byte_xor_unknown() {
        let opcode = value(2); // XOR opcode
        let a = default();
        let b = mask(0x0f);
        let c = mask(0xa0);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(2));
        assert_eq!(result[1], mask(0xaf));
        assert_eq!(result[2], mask(0x0f));
        assert_eq!(result[3], mask(0xa0));
    }

    #[test]
    fn test_u8_range_unknown() {
        let opcode = value(3);
        let a = default();
        let b = default();
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(3));
        assert_eq!(result[1], value(0));
        assert_eq!(result[2], mask(0xff));
        assert_eq!(result[3], mask(0xff));
    }

    #[test]
    fn test_ltu_known() {
        let opcode = value(4);
        let a = default();
        let b = value(100);
        let c = value(200);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(4));
        assert_eq!(result[1], value(1));
        assert_eq!(result[2], value(100));
        assert_eq!(result[3], value(200));

        let opcode = value(4);
        let a = default();
        let b = value(200);
        let c = value(100);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result[1], value(0));
    }

    #[test]
    fn test_ltu_unknown() {
        let opcode = value(4);
        let a = default();
        let b = default();
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(4));
        assert_eq!(result[1], mask(0x1));
        assert_eq!(result[2], mask(0xff));
        assert_eq!(result[3], mask(0xff));
    }

    #[test]
    fn test_msb_known() {
        let opcode = value(5);
        let a = default();
        let b = value(0b10101010);
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(5));
        assert_eq!(result[1], value(1));
        assert_eq!(result[2], value(0b10101010));
        assert_eq!(result[3], value(0));

        let opcode = value(5);
        let a = default();
        let b = value(0b01010101);
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result[1], value(0));
    }

    #[test]
    fn test_msb_unknown() {
        let opcode = value(5);
        let a = default();
        let b = default();
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(5));
        assert_eq!(result[1], mask(0x1));
        assert_eq!(result[2], mask(0xff));
        assert_eq!(result[3], value(0));
    }

    #[test]
    fn test_sr_known() {
        let opcode = value(6);
        let a = default();
        let b = value(0b11110000);
        let c = value(4);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(6));
        assert_eq!(result[1], value(0b00001111));
        assert_eq!(result[2], value(0b11110000));
        assert_eq!(result[3], value(4));

        let opcode = value(6);
        let a = default();
        let b = value(0b11110000);
        let c = value(8);

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result[1], value(0));
    }

    #[test]
    fn test_sr_unknown() {
        let opcode = value(6);
        let a = default();
        let b = default();
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(6));
        assert_eq!(result[1], mask(0xff));
        assert_eq!(result[2], mask(0xff));
        assert_eq!(result[3], mask(0xff));
    }

    #[test]
    fn test_range() {
        let opcode = value(7);
        let a = default();
        let b = value(8);
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result.len(), 4);
        assert_eq!(result[0], value(7));
        assert_eq!(result[1], mask(0xff));
        assert_eq!(result[2], value(8));
        assert_eq!(result[3], value(0));

        let opcode = value(7);
        let a = default();
        let b = value(16);
        let c = default();

        let result = run(InteractionKind::Byte, vec![opcode, a, b, c], BabyBearField::one());

        assert_eq!(result[1], mask(0xffff));
        assert_eq!(result[2], value(16));
    }
}
