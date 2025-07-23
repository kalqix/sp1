use itertools::repeat_n;
use powdr_autoprecompiles::constraint_optimizer::IsBusStateful;
use powdr_constraint_solver::{
    constraint_system::{BusInteraction, BusInteractionHandler},
    range_constraint::RangeConstraint,
};
use powdr_number::{BabyBearField, FieldElement};
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

    // The range constraint on `a` depends on the opcode.
    let (a, b, c) = match opcode.try_to_single_value().map(|v| v.to_degree()) {
        // AND: a = b & c
        Some(0) => {
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
        Some(1) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let a = BabyBearField::from(b_val.to_degree() | c_val.to_degree());
                (RangeConstraint::from_value(a), b, c)
            } else {
                let a = b.disjunction(&c);
                (a, b, c)
            }
        }
        // XOR: a = b ^ c
        Some(2) => {
            if let (Some(b_val), Some(c_val)) = (b.try_to_single_value(), c.try_to_single_value()) {
                let a = BabyBearField::from(b_val.to_degree() ^ c_val.to_degree());
                (RangeConstraint::from_value(a), b, c)
            } else {
                let a = b.disjunction(&c);
                (a, b, c)
            }
        }
        // U8Range: assert(a == 0 && b < 256 && c < 256)
        Some(3) => (
            RangeConstraint::from_value(BabyBearField::zero()),
            byte_constraint(),
            byte_constraint(),
        ),
        // LTU: a = b < c
        Some(4) => {
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
        Some(5) => {
            if let Some(b_val) = b.try_to_single_value() {
                assert!(b_val.to_degree() < 256);
                let result = BabyBearField::from((b_val.to_degree() >> 7) & 1);
                (RangeConstraint::from_value(result), b, zero)
            } else {
                (RangeConstraint::from_mask(0x1u64), b, zero)
            }
        }
        // SR: a = b >> c
        Some(6) => {
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
        Some(7) => {
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
        Some(unexpected_opcode) => {
            unreachable!("Unknown opcode in byte bus interaction: {unexpected_opcode}")
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
