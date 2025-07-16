use core::fmt;
use std::sync::Arc;

use powdr_autoprecompiles::{
    expression::AlgebraicReference, SymbolicBusInteraction, SymbolicConstraint, SymbolicMachine,
};
use powdr_expression::{
    AlgebraicBinaryOperation, AlgebraicBinaryOperator, AlgebraicExpression,
    AlgebraicUnaryOperation, AlgebraicUnaryOperator,
};

use slop_air::{Air, BaseAir, PairCol, VirtualPairCol};
use slop_algebra::PrimeField32;
use slop_uni_stark::{get_symbolic_constraints, Entry, SymbolicExpression, SymbolicVariable};
use sp1_stark::{
    air::{InteractionScope, MachineAir},
    Interaction, InteractionBuilder, PROOF_MAX_NUM_PVS,
};

use crate::riscv::RiscvAir;

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
    let (sends, receives) = builder.interactions();
    let bus_interactions = sends
        .into_iter()
        .map(|interaction| sp1_bus_interaction_to_powdr(&interaction, &column_names))
        // TODO: Likely, chaining here is a problem, because we lose the information about the
        // order of the interactions.
        .chain(receives.into_iter().map(|interaction| {
            let mut interaction = sp1_bus_interaction_to_powdr(&interaction, &column_names)?;
            // Negate the multiplicity for receives.
            interaction.mult = -interaction.mult;
            Ok(interaction)
        }))
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

    let id = interaction.kind as u64;
    let mult = virtual_col_to_algebraic(&interaction.multiplicity, columns)?;
    let args = interaction
        .values
        .iter()
        .map(|e| virtual_col_to_algebraic(e, columns))
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

fn virtual_col_to_algebraic<F: PrimeField32>(
    column: &VirtualPairCol<F>,
    columns: &[Arc<String>],
) -> Result<AlgebraicExpression<F, AlgebraicReference>, UnsupportedConstraintError> {
    // Convert columns and weights to algebraic expressions.
    let column_weights = column
        .column_weights
        .iter()
        .map(|(col, weight)| {
            let ref_col = match col {
                PairCol::Preprocessed(_i) => {
                    return Err(UnsupportedConstraintError("Preprocessed column".to_string()))
                }
                PairCol::Main(i) => AlgebraicExpression::Reference(AlgebraicReference {
                    name: columns[*i].clone(),
                    id: *i as u64,
                }),
            };
            Ok((ref_col, number_to_algebraic(weight)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let constant = number_to_algebraic(&column.constant);

    Ok(column_weights
        .into_iter()
        .map(|(column, weight)| weight * column)
        .fold(AlgebraicExpression::Number(F::zero()), |acc, expr| acc + expr)
        + constant)
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
