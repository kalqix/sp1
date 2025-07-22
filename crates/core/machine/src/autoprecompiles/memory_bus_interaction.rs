use powdr_autoprecompiles::{
    expression::AlgebraicReference,
    memory_optimizer::{MemoryBusInteraction, MemoryBusInteractionConversionError, MemoryOp},
};
use powdr_constraint_solver::{
    constraint_system::BusInteraction, grouped_expression::GroupedExpression,
};
use powdr_number::{BabyBearField, FieldElement};

pub struct Sp1MemoryBusInteraction {
    addr: MemoryAddress,
    data: Vec<GroupedExpression<BabyBearField, AlgebraicReference>>,
    op: MemoryOp,
}

#[derive(Clone, Hash, Eq, PartialEq)]
/// The memory address, represented as 3 16-Bit limbs in little-endian order.
// TODO: It might make sense to add an artificial address space field, to make sure that the
// memory optimizer does not redo register accesses if a RAM access happened.
// It is guaranteed by the constraints of SP1 that RAM accesses don't go to the register memory
// space (RAM access must go to addresses > 2^16), but the memory optimizer likely doesn't infer
// that.
pub struct MemoryAddress([GroupedExpression<BabyBearField, AlgebraicReference>; 3]);

impl IntoIterator for MemoryAddress {
    type Item = GroupedExpression<BabyBearField, AlgebraicReference>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        Vec::from(self.0).into_iter()
    }
}

impl MemoryBusInteraction<BabyBearField, AlgebraicReference> for Sp1MemoryBusInteraction {
    type Address = MemoryAddress;

    fn try_from_bus_interaction(
        bus_interaction: &BusInteraction<GroupedExpression<BabyBearField, AlgebraicReference>>,
        memory_bus_id: u64,
    ) -> Result<Option<Self>, MemoryBusInteractionConversionError> {
        // Format is: (clk_high, clk_low, addr (3 limbs), value (4 limbs))
        // See: crates/core/machine/src/air/memory.rs

        match bus_interaction.bus_id.try_to_number() {
            None => return Err(MemoryBusInteractionConversionError),
            Some(id) if id == memory_bus_id.into() => {}
            Some(_) => return Ok(None),
        }

        let op = match bus_interaction.multiplicity.try_to_number() {
            // SP1 *sends* the previous values and *receives* the new values.
            Some(n) if n == 1.into() => MemoryOp::GetPrevious,
            Some(n) if n == (-1).into() => MemoryOp::SetNew,
            _ => return Err(MemoryBusInteractionConversionError),
        };

        let [_clk_high, _clk_low, addr0, addr1, addr2, data0, data1, data2, data3] =
            &bus_interaction.payload[..]
        else {
            panic!()
        };
        let addr = MemoryAddress([addr0.clone(), addr1.clone(), addr2.clone()]);
        let data = vec![data0.clone(), data1.clone(), data2.clone(), data3.clone()];
        Ok(Some(Sp1MemoryBusInteraction { addr, data, op }))
    }

    fn addr(&self) -> Self::Address {
        self.addr.clone()
    }

    fn data(&self) -> &[GroupedExpression<BabyBearField, AlgebraicReference>] {
        &self.data
    }

    fn op(&self) -> powdr_autoprecompiles::memory_optimizer::MemoryOp {
        self.op
    }

    fn register_address(&self) -> Option<usize> {
        if self.addr.0[1] == GroupedExpression::from_number(0.into())
            && self.addr.0[2] == GroupedExpression::from_number(0.into())
        {
            // If the address is in the form of [addr, 0, 0], it is a register access.
            // The first limb is the register number.
            Some(self.addr.0[0].try_to_number().unwrap().to_arbitrary_integer().try_into().unwrap())
        } else {
            None
        }
    }
}
