use core::fmt;
use std::{collections::BTreeMap, sync::Arc};

use itertools::Itertools;
use powdr_autoprecompiles::{
    bus_map::BusType, expression::AlgebraicReference, powdr::UniqueReferences,
    SymbolicBusInteraction, SymbolicConstraint, SymbolicMachine,
};
use powdr_constraint_solver::grouped_expression::GroupedExpression;
use powdr_expression::{
    visitors::ExpressionVisitable, AlgebraicBinaryOperation, AlgebraicBinaryOperator,
    AlgebraicExpression, AlgebraicUnaryOperation, AlgebraicUnaryOperator,
};

use powdr_number::{BabyBearField, ExpressionConvertible, FieldElement};
use slop_air::{Air, BaseAir};
use slop_algebra::PrimeField32;
use slop_uni_stark::{get_symbolic_constraints, Entry, SymbolicExpression, SymbolicVariable};
use sp1_stark::{
    air::{InteractionScope, MachineAir},
    PROOF_MAX_NUM_PVS,
};

use crate::{
    autoprecompiles::{
        bus_map::sp1_bus_map,
        interaction_builder::{Interaction, InteractionBuilder},
    },
    riscv::RiscvAir,
};

pub fn sort_memory_interactions<F: PrimeField32>(
    machine: SymbolicMachine<F>,
) -> SymbolicMachine<F> {
    let bus_map = sp1_bus_map();
    let memory_bus_id = bus_map.get_bus_id(&BusType::Memory).unwrap();
    let (memory_bus_interactions, other_interactions): (Vec<_>, Vec<_>) =
        machine.bus_interactions.into_iter().partition(|bi| bi.id == memory_bus_id);

    let memory_bus_interactions = memory_bus_interactions
        .into_iter()
        .chunks(2)
        .into_iter()
        .map(|interaction_pair| {
            let [send, receive] = interaction_pair.collect::<Vec<_>>().try_into().unwrap();
            (send, receive)
        })
        .sorted_by_key(|(_send, receive)| {
            // Format is: (clk_high, clk_low, addr (3 limbs), value (4 limbs))
            let [_clk_high, clk_low, _addr0, _addr1, _addr2, _data0, _data1, _data2, _data3] =
                &receive.args[..]
            else {
                panic!();
            };

            let clk_low: GroupedExpression<BabyBearField, _> = clk_low.to_expression(
                &|n| {
                    GroupedExpression::from_number(BabyBearField::from_bytes_le(
                        &n.as_canonical_u32().to_le_bytes(),
                    ))
                },
                &|reference| GroupedExpression::from_unknown_variable(reference.clone()),
            );
            let (_, _, offset) = clk_low.components();
            offset.to_degree()
        })
        .flat_map(|(send, receive)| [send, receive])
        .collect::<Vec<_>>();

    SymbolicMachine {
        constraints: machine.constraints,
        bus_interactions: other_interactions.into_iter().chain(memory_bus_interactions).collect(),
    }
}

/// Reassigns IDs in the symbolic machine to be dense, starting from 0.
pub fn densify_ids<F: PrimeField32>(machine: SymbolicMachine<F>) -> SymbolicMachine<F> {
    let id_map = machine
        .unique_references()
        .map(|r| r.id)
        .sorted()
        .enumerate()
        .map(|(new_id, old_id)| (old_id, new_id as u64))
        .collect::<BTreeMap<_, _>>();

    SymbolicMachine {
        constraints: machine
            .constraints
            .into_iter()
            .map(|c| SymbolicConstraint { expr: densify_ids_expr(c.expr, &id_map) })
            .collect(),
        bus_interactions: machine
            .bus_interactions
            .into_iter()
            .map(|bi| densify_ids_bus_interaction(bi, &id_map))
            .collect(),
    }
}

fn densify_ids_expr<F>(
    mut expr: AlgebraicExpression<F, AlgebraicReference>,
    id_map: &BTreeMap<u64, u64>,
) -> AlgebraicExpression<F, AlgebraicReference> {
    expr.pre_visit_expressions_mut(&mut |e| {
        if let AlgebraicExpression::Reference(ref mut r) = e {
            r.id = *id_map.get(&r.id).unwrap();
        }
    });
    expr
}

fn densify_ids_bus_interaction<F>(
    interaction: SymbolicBusInteraction<F>,
    id_map: &BTreeMap<u64, u64>,
) -> SymbolicBusInteraction<F> {
    SymbolicBusInteraction {
        id: interaction.id,
        mult: densify_ids_expr(interaction.mult, id_map),
        args: interaction.args.into_iter().map(|arg| densify_ids_expr(arg, id_map)).collect(),
    }
}

pub fn air_to_symbolic_machine<F: PrimeField32>(
    air: &RiscvAir<F>,
) -> Result<SymbolicMachine<F>, UnsupportedConstraintError> {
    let column_names = air.column_names().into_iter().map(Arc::new).collect::<Vec<_>>();

    // Get constraints
    let constraints = get_symbolic_constraints(air, air.preprocessed_width(), PROOF_MAX_NUM_PVS);
    let constraints = constraints
        .into_iter()
        .map(|c| Ok(SymbolicConstraint { expr: symbolic_to_algebraic(&c, &column_names)? }))
        .collect::<Result<Vec<_>, _>>()?;

    // Get interactions
    let mut builder = InteractionBuilder::new(air.preprocessed_width(), air.width());
    air.eval(&mut builder);
    let interactions = builder.interactions();
    let bus_interactions = interactions
        .into_iter()
        .map(|interaction| sp1_bus_interaction_to_powdr(&interaction, &column_names))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SymbolicMachine { constraints, bus_interactions })
}

fn sp1_bus_interaction_to_powdr<F: PrimeField32>(
    interaction: &Interaction<F>,
    columns: &[Arc<String>],
) -> Result<SymbolicBusInteraction<F>, UnsupportedConstraintError> {
    match interaction.scope {
        InteractionScope::Global => {
            return Err(UnsupportedConstraintError("Global interaction".to_string()));
        }
        InteractionScope::Local => {}
    }

    let id = interaction.message.kind as u64;
    let mult = symbolic_to_algebraic(&interaction.message.multiplicity, columns)?;
    let args = interaction
        .message
        .values
        .iter()
        .map(|e| symbolic_to_algebraic(e, columns))
        .collect::<Result<_, _>>()?;

    Ok(SymbolicBusInteraction { id, mult, args })
}

#[derive(Debug)]
pub struct UnsupportedConstraintError(pub String);

impl fmt::Display for UnsupportedConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn number_to_algebraic<F: PrimeField32>(value: &F) -> AlgebraicExpression<F, AlgebraicReference> {
    AlgebraicExpression::Number(*value)
}

fn symbolic_to_algebraic<F: PrimeField32>(
    expr: &SymbolicExpression<F>,
    columns: &[Arc<String>],
) -> Result<AlgebraicExpression<F, AlgebraicReference>, UnsupportedConstraintError> {
    Ok(match expr {
        SymbolicExpression::Constant(c) => number_to_algebraic(c),
        SymbolicExpression::Add { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns)?),
                right: Box::new(symbolic_to_algebraic(y, columns)?),
                op: AlgebraicBinaryOperator::Add,
            })
        }
        SymbolicExpression::Sub { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns)?),
                right: Box::new(symbolic_to_algebraic(y, columns)?),
                op: AlgebraicBinaryOperator::Sub,
            })
        }
        SymbolicExpression::Mul { x, y, .. } => {
            AlgebraicExpression::BinaryOperation(AlgebraicBinaryOperation {
                left: Box::new(symbolic_to_algebraic(x, columns)?),
                right: Box::new(symbolic_to_algebraic(y, columns)?),
                op: AlgebraicBinaryOperator::Mul,
            })
        }
        SymbolicExpression::Neg { x, .. } => {
            AlgebraicExpression::UnaryOperation(AlgebraicUnaryOperation {
                expr: Box::new(symbolic_to_algebraic(x, columns)?),
                op: AlgebraicUnaryOperator::Minus,
            })
        }
        SymbolicExpression::Variable(SymbolicVariable { entry, index, .. }) => match entry {
            Entry::Main { offset } => {
                if *offset != 0 {
                    return Err(UnsupportedConstraintError(format!("Nonzero offset: {offset}")));
                };
                let name = columns.get(*index).unwrap_or_else(|| {
                    panic!("Column index out of bounds: {index}\nColumns: {columns:?}");
                });
                AlgebraicExpression::Reference(AlgebraicReference {
                    name: name.clone(),
                    id: *index as u64,
                })
            }
            Entry::Preprocessed { .. } => {
                return Err(UnsupportedConstraintError("Preprocessed column".to_string()))
            }
            Entry::Permutation { .. } => {
                return Err(UnsupportedConstraintError("Permutation column".to_string()))
            }
            Entry::Public => {
                return Err(UnsupportedConstraintError("Public reference".to_string()))
            }
            Entry::Challenge => {
                return Err(UnsupportedConstraintError("Challenge reference".to_string()))
            }
        },
        SymbolicExpression::IsFirstRow => {
            return Err(UnsupportedConstraintError("is_first_row reference".to_string()))
        }
        SymbolicExpression::IsLastRow => {
            return Err(UnsupportedConstraintError("is_last_row reference".to_string()))
        }
        SymbolicExpression::IsTransition => {
            return Err(UnsupportedConstraintError("is_transition reference".to_string()))
        }
    })
}
