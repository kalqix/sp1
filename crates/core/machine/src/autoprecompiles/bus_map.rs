use powdr_autoprecompiles::bus_map::{BusMap, BusType};

pub fn sp1_bus_map() -> BusMap {
    // Mapping from: crates/stark/src/lookup/interaction.rs
    BusMap::from_id_type_pairs([
        (1, BusType::Memory),
        (2, BusType::PcLookup),
        (7, BusType::ExecutionBridge),
    ])
}
