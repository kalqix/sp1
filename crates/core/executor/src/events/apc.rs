/// Inspired from `events/precompiles/mod.rs`
use crate::{
    deserialize_hashmap_as_vec,
    events::{MemoryLocalEvent, PrecompileLocalMemory},
    serialize_hashmap_as_vec,
};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::ExecutionRecord;

use super::PageProtLocalEvent;

#[derive(Deserialize, Serialize, Debug, Clone, deepsize2::DeepSizeOf)]
/// Represents an apc event in the executor.
pub struct ApcEvent {
    /// The apc id
    pub id: u64,
    /// The record of the original instructions executed by the apc.
    pub record: ExecutionRecord,
}

/// A record of all the apc events.
#[derive(Clone, Debug, Serialize, Deserialize, Default, deepsize2::DeepSizeOf)]
pub struct ApcEvents {
    #[serde(serialize_with = "serialize_hashmap_as_vec")]
    #[serde(deserialize_with = "deserialize_hashmap_as_vec")]
    /// The apc events mapped by apc id.
    pub events: HashMap<u64, Vec<ApcEvent>>,
}

impl ApcEvents {
    pub(crate) fn append(&mut self, other: &mut ApcEvents) {
        for (id, event) in other.events.iter_mut() {
            if !event.is_empty() {
                self.events.entry(*id).or_default().append(event);
            }
        }
    }

    #[inline]
    /// Add a precompile event for a given apc id.
    pub fn add_event(&mut self, apc_id: u64, event: ApcEvent) {
        assert_eq!(apc_id, event.id);
        self.events.entry(apc_id).or_default().push(event);
    }

    /// Checks if the precompile events are empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get all the precompile events.
    pub fn all_events(&self) -> impl Iterator<Item = &ApcEvent> {
        self.events.values().flatten()
    }

    /// Get the number of precompile events.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Get all the precompile events for a given apc id.
    #[inline]
    #[must_use]
    pub fn get_events(&self, apc_id: u64) -> Option<&Vec<ApcEvent>> {
        self.events.get(&apc_id)
    }

    /// Get all the local events from all the precompile events.
    pub(crate) fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_mem_events());
        }

        iterators.into_iter().flatten()
    }

    /// Get all the local page prot events from all the precompile events.
    pub(crate) fn get_local_page_prot_events(&self) -> impl Iterator<Item = &PageProtLocalEvent> {
        let mut iterators = Vec::new();

        for (_, events) in self.events.iter() {
            iterators.push(events.get_local_page_prot_events());
        }

        iterators.into_iter().flatten()
    }
}

impl PrecompileLocalMemory for Vec<ApcEvent> {
    fn get_local_mem_events(&self) -> impl IntoIterator<Item = &MemoryLocalEvent> {
        self.iter()
            .flat_map(|event| event.record.get_local_mem_events())
            .collect::<Vec<_>>() // collecting because otherwise we get a recursive opaque type error
            .into_iter()
    }

    fn get_local_page_prot_events(&self) -> impl IntoIterator<Item = &PageProtLocalEvent> {
        todo!();
        std::iter::empty()
    }
}
