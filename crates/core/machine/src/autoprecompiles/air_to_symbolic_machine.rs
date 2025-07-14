use std::sync::Arc;

use powdr_autoprecompiles::{
    expression::AlgebraicReference, SymbolicBusInteraction, SymbolicConstraint, SymbolicMachine,
};
use powdr_expression::{
    AlgebraicBinaryOperation, AlgebraicBinaryOperator, AlgebraicExpression,
    AlgebraicUnaryOperation, AlgebraicUnaryOperator,
};

use powdr_number::FieldElement;
use slop_air::{Air, BaseAir, PairCol, VirtualPairCol};
use slop_algebra::PrimeField32;
use slop_uni_stark::{get_symbolic_constraints, Entry, SymbolicExpression, SymbolicVariable};
use sp1_stark::{air::MachineAir, Interaction, InteractionBuilder, PROOF_MAX_NUM_PVS};

use crate::riscv::RiscvAir;

pub fn air_to_symbolic_machine<F: PrimeField32, P: FieldElement>(
    air: &RiscvAir<F>,
) -> Result<SymbolicMachine<P>, UnsupportedReferenceError> {
    // TODO: Properly extract column names.
    let column_names = (0..10000).map(|i| Arc::new(format!("var_{i}"))).collect::<Vec<_>>();

    let constraints = get_symbolic_constraints(air, air.preprocessed_width(), PROOF_MAX_NUM_PVS);

    let constraints = constraints
        .into_iter()
        .map(|c| Ok(SymbolicConstraint { expr: symbolic_to_algebraic(&c, &column_names)? }))
        .collect::<Result<Vec<_>, _>>()?;
    let mut builder = InteractionBuilder::new(air.preprocessed_width(), air.width());
    air.eval(&mut builder);
    let (sends, receives) = builder.interactions();
    let bus_interactions = sends
        .into_iter()
        .map(|interaction| sp1_bus_interaction_to_powdr(&interaction, &column_names))
        // TODO: Likely, this is a problem, because we lose the information about the
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

fn sp1_bus_interaction_to_powdr<F: PrimeField32, P: FieldElement>(
    interaction: &Interaction<F>,
    columns: &[Arc<String>],
) -> Result<SymbolicBusInteraction<P>, UnsupportedReferenceError> {
    let id = interaction.kind as u64;

    let mult = virtual_col_to_algebraic(&interaction.multiplicity, columns)?;
    let args = interaction
        .values
        .iter()
        .map(|e| virtual_col_to_algebraic(e, columns))
        .collect::<Result<_, _>>()?;

    Ok(SymbolicBusInteraction { id, mult, args })
}

/// An unsupported SP1 reference appeared, e.g., a non-zero offset or a reference to
/// is_first_row, is_last_row, is_transition, or a preprocessed column.
#[derive(Debug)]
pub struct UnsupportedReferenceError(pub String);

fn number_to_algebraic<T: PrimeField32, P: FieldElement>(
    value: &T,
) -> AlgebraicExpression<P, AlgebraicReference> {
    AlgebraicExpression::Number(P::from_bytes_le(&value.as_canonical_u32().to_le_bytes()))
}

fn virtual_col_to_algebraic<F: PrimeField32, P: FieldElement>(
    column: &VirtualPairCol<F>,
    columns: &[Arc<String>],
) -> Result<AlgebraicExpression<P, AlgebraicReference>, UnsupportedReferenceError> {
    let column_weights = column
        .column_weights
        .iter()
        .map(|(col, weight)| {
            let ref_col = match col {
                PairCol::Preprocessed(_i) => {
                    return Err(UnsupportedReferenceError("Preprocessed column".to_string()))
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
        .fold(AlgebraicExpression::Number(P::zero()), |acc, expr| acc + expr)
        + constant)
}

fn symbolic_to_algebraic<T: PrimeField32, P: FieldElement>(
    expr: &SymbolicExpression<T>,
    columns: &[Arc<String>],
) -> Result<AlgebraicExpression<P, AlgebraicReference>, UnsupportedReferenceError> {
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
                    return Err(UnsupportedReferenceError(format!("Nonzero offset: {offset}")));
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
                return Err(UnsupportedReferenceError("Preprocessed column".to_string()))
            }
            Entry::Permutation { .. } => {
                return Err(UnsupportedReferenceError("Permutation column".to_string()))
            }
            Entry::Public => return Err(UnsupportedReferenceError("Public reference".to_string())),
            Entry::Challenge => {
                return Err(UnsupportedReferenceError("Challenge reference".to_string()))
            }
        },
        SymbolicExpression::IsFirstRow => {
            return Err(UnsupportedReferenceError("is_first_row reference".to_string()))
        }
        SymbolicExpression::IsLastRow => {
            return Err(UnsupportedReferenceError("is_last_row reference".to_string()))
        }
        SymbolicExpression::IsTransition => {
            return Err(UnsupportedReferenceError("is_transition reference".to_string()))
        }
    })
}
