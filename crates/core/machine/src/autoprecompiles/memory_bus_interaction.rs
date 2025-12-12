use num::{One, Zero};
use powdr_autoprecompiles::memory_optimizer::{
    MemoryBusInteraction, MemoryBusInteractionConversionError, MemoryOp,
};
use powdr_constraint_solver::{
    constraint_system::BusInteraction, grouped_expression::GroupedExpression,
};
use powdr_number::{FieldElement, KoalaBearField};
use std::{
    fmt::Display,
    hash::Hash,
    iter::{once, Chain},
};
