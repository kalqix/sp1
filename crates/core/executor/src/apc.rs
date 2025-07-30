use crate::{Executor, Instruction};

pub struct Apc<'a> {
    pub id: u64,
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
