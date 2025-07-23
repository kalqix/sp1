use std::{iter::Sum, ops::Add};

use powdr_autoprecompiles::{InstructionHandler, SymbolicMachine};

use slop_baby_bear::BabyBear;
use sp1_core_executor::Instruction;

use crate::autoprecompiles::instruction_handler::Sp1InstructionHandler;

#[derive(Clone, Copy, PartialEq, Default, Eq, Debug)]
pub struct AirStats {
    pub main_columns: usize,
    pub constraints: usize,
    pub bus_interactions: usize,
}

impl AirStats {
    pub fn new<F: Clone + Ord + std::fmt::Display>(machine: &SymbolicMachine<F>) -> Self {
        Self {
            main_columns: machine.main_columns().count(),
            constraints: machine.constraints.len(),
            bus_interactions: machine.bus_interactions.len(),
        }
    }
}

impl Add for AirStats {
    type Output = AirStats;
    fn add(self, rhs: AirStats) -> AirStats {
        AirStats {
            main_columns: self.main_columns + rhs.main_columns,
            constraints: self.constraints + rhs.constraints,
            bus_interactions: self.bus_interactions + rhs.bus_interactions,
        }
    }
}

impl Sum<AirStats> for AirStats {
    fn sum<I: Iterator<Item = AirStats>>(iter: I) -> AirStats {
        iter.fold(AirStats::default(), Add::add)
    }
}

pub fn evaluate_apc(
    basic_block: &[Instruction],
    machine: &SymbolicMachine<impl Clone + Ord + std::fmt::Display>,
) -> String {
    let instruction_handler = Sp1InstructionHandler::<BabyBear>::new();
    let stats_before = basic_block
        .iter()
        .map(|instruction| instruction_handler.get_instruction_air(&(*instruction).into()).unwrap())
        .map(AirStats::new)
        .sum::<AirStats>();
    let stats_after = AirStats::new(machine);
    format!(
        "APC advantage:\n  - Main columns: {}\n  - Bus interactions: {}\n  - Constraints: {}",
        render_stat(stats_before.main_columns, stats_after.main_columns),
        render_stat(stats_before.bus_interactions, stats_after.bus_interactions),
        render_stat(stats_before.constraints, stats_after.constraints)
    )
}

fn render_stat(before: usize, after: usize) -> String {
    let effectiveness = before as f64 / after as f64;
    format!("{before} -> {after} (effectiveness: {effectiveness:.2})")
}
