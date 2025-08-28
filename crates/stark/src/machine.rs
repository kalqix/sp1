use derive_where::derive_where;
use slop_algebra::Field;
use std::collections::BTreeSet;

use crate::{air::MachineAir, Chip, MachineRecord};

/// A shape for a machine.
#[derive_where(Debug; A: MachineAir<F>)]
#[derive_where(Clone)]
pub struct MachineShape<F: Field, A> {
    /// The chip clusters.
    pub chip_clusters: Vec<BTreeSet<Chip<F, A>>>,
}

impl<F: Field, A: MachineAir<F>> MachineShape<F, A> {
    /// Create a single shape that always includes all the chips.
    #[must_use]
    pub fn all(chips: &[Chip<F, A>]) -> Self {
        let chip_clusters = vec![chips.iter().cloned().collect()];
        Self { chip_clusters }
    }

    /// Create a new shape from a list of chip clusters.
    #[must_use]
    pub const fn new(chip_clusters: Vec<BTreeSet<Chip<F, A>>>) -> Self {
        Self { chip_clusters }
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.chip_clusters
            .iter()
            .filter(|cluster| chips.is_subset(cluster))
            .min_by_key(|cluster| cluster.len())
    }
}

/// A STARK for proving RISC-V execution.
#[derive_where(Debug; A: MachineAir<F>)]
#[derive_where(Clone)]
pub struct Machine<F: Field, A> {
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<F, A>>,
    /// The number of public values elements that the machine uses
    num_pv_elts: usize,
    /// The shape of the machine.
    shape: MachineShape<F, A>,
}

impl<F, A> Machine<F, A>
where
    F: Field,
    A: MachineAir<F>,
{
    /// Calculates the cost of each APC as its air width, which is the number of columns.
    /// This is used in the cost estimator to determine when to segment.
    #[must_use]
    pub fn apc_costs(&self) -> Vec<u64> {
        // Searching name by "ApcChip" is more of a hack, but is the best that we can do
        // because pattern matching on RiscvAirWithApcs::ApcChip requires dependency on
        // sp1-core-machine which depends on this crate and thus creates a circular
        // dependency.
        self.chips
            .iter()
            .filter_map(|chip| {
                if chip.name().starts_with("ApcChip") {
                    // We also rely on the fact that APC id is the same as ApcChip insertion order
                    // in Machine. APC id is the index of the returned vector.
                    Some(chip.air.width() as u64)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Creates a new [`StarkMachine`].
    #[must_use]
    pub const fn new(
        chips: Vec<Chip<F, A>>,
        num_pv_elts: usize,
        shape: MachineShape<F, A>,
    ) -> Self {
        Self { chips, num_pv_elts, shape }
    }

    /// Returns the chips in the machine.
    #[must_use]
    pub fn chips(&self) -> &[Chip<F, A>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    #[must_use]
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns the shape of the machine.
    #[must_use]
    pub const fn shape(&self) -> &MachineShape<F, A> {
        &self.shape
    }

    /// Returns the smallest shape cluster that contains all the chips with given names.
    #[must_use]
    pub fn smallest_cluster(&self, chips: &BTreeSet<Chip<F, A>>) -> Option<&BTreeSet<Chip<F, A>>> {
        self.shape.smallest_cluster(chips)
    }

    /// Generates the dependencies of the given records.
    #[allow(clippy::needless_for_each)]
    pub fn generate_dependencies(
        &self,
        records: &mut [A::Record],
        chips_filter: Option<&[String]>,
    ) {
        let chips = self
            .chips
            .iter()
            .filter(|chip| {
                if let Some(chips_filter) = chips_filter {
                    chips_filter.contains(&chip.name())
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        records.iter_mut().for_each(|record| {
            chips.iter().for_each(|chip| {
                let mut output = A::Record::default();
                chip.generate_dependencies(record, &mut output);
                record.append(&mut output);
            });
            // tracing::debug_span!("register nonces").in_scope(|| record.register_nonces(opts));
        });
    }

    /// Customizes the program using each chip.
    pub fn customize_program(&self, program: A::Program) -> A::Program {
        self.chips.iter().fold(program, |program, chip| chip.customize_program(program))
    }
}
