use std::sync::Arc;

use powdr_autoprecompiles::adapter::AdapterApc;
use slop_algebra::PrimeField32;
use sp1_stark::air::MachineAir;

use crate::autoprecompiles::{chip::dummy::DummyChip, Sp1ApcAdapter};

mod apc_chip;
mod dummy;

pub use apc_chip::ApcChip;

/// Represents a chip that may or may not contain an APC
use sp1_stark::air::InteractionScope;
#[derive(MachineAir)]
pub enum MaybeApcChip<F: PrimeField32> {
    Apc(ApcChip<F>),
    Dummy(DummyChip),
}

impl<F: PrimeField32> MaybeApcChip<F> {
    /// Creates a new `MaybeApcChip` from an optional APC.
    pub fn new(apc: Option<(Arc<AdapterApc<Sp1ApcAdapter>>, usize)>) -> Self {
        match apc {
            Some((apc, id)) => MaybeApcChip::Apc(ApcChip::new(apc, id)),
            None => MaybeApcChip::Dummy(DummyChip),
        }
    }
}
