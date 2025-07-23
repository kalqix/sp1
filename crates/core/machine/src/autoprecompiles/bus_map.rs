use std::fmt::Display;

use powdr_autoprecompiles::bus_map::BusType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sp1SpecificBuses {
    Byte,
}

impl Display for Sp1SpecificBuses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sp1SpecificBuses::Byte => write!(f, "BYTE"),
        }
    }
}

pub type BusMap = powdr_autoprecompiles::bus_map::BusMap<Sp1SpecificBuses>;

pub fn sp1_bus_map() -> BusMap {
    // Mapping from: crates/stark/src/lookup/interaction.rs
    BusMap::from_id_type_pairs([
        (1, BusType::Memory),
        (2, BusType::PcLookup),
        (5, BusType::Other(Sp1SpecificBuses::Byte)),
        (7, BusType::ExecutionBridge),
    ])
}
