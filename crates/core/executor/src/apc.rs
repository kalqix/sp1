use crate::{Executor, Instruction};

/// Represents an autoprecompile (APC) in the executor.
pub struct Apc<'a> {
    /// The id of the autoprecompile, used for identification.
    pub id: u64,
    /// The original instructions that led to this autoprecompile
    pub original_instructions: Vec<Instruction>,
    pub executor: Executor<'a>,
}

impl<'a> Apc<'a> {
    pub fn new(id: u64, (from, to): (usize, usize), executor: Executor<'a>) -> Self {
        Self {
            id,
            original_instructions: executor
                .program
                .instructions
                .original_instructions_for_range(from, to),
            executor,
        }
    }
}
