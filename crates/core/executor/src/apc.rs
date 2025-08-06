use std::sync::Arc;

use crate::{Executor, Program, SP1Context, SP1CoreOpts};

/// Represents an autoprecompile (APC) in the executor.
pub struct Apc<'a> {
    /// The id of the autoprecompile, used for identification.
    pub id: u64,
    /// The number of original instructions in the autoprecompile.
    pub original_instructions_count: usize,
    /// A single executor which is used each time the autoprecompile is executed.
    /// Before executing the autoprecompile, it is synced with the current state of main execution.
    pub executor: Executor<'a>,
}

impl<'a> Apc<'a> {
    pub fn new(id: u64, length: usize, executor: Executor<'a>) -> Self {
        assert!(length > 0, "APC length must be greater than 0");
        Self { id, original_instructions_count: length, executor }
    }
}

/// A collection of APCs that are available for the execution.
#[derive(Default)]
pub struct Apcs<'a> {
    /// The APCs that are available for this execution.
    pub apcs: Vec<Apc<'a>>,
}

impl<'a, 'b> IntoIterator for &'b Apcs<'a> {
    type Item = &'b Apc<'a>;
    type IntoIter = std::slice::Iter<'b, Apc<'a>>;

    fn into_iter(self) -> Self::IntoIter {
        self.apcs.iter()
    }
}

impl<'a> Apcs<'a> {
    /// Creates a new Apcs instance from a program and options.
    pub fn new(program: &Program, opts: &SP1CoreOpts, context: &SP1Context<'a>) -> Self {
        // Create a program with no APCs which is used for executing the APCs based on their
        // original instructions.
        let apc_free_program = {
            let mut p = program.clone();
            p.instructions.clear_apcs();
            p
        };
        let apc_free_program = Arc::new(apc_free_program);

        let apcs = program
            .instructions
            .apcs()
            .enumerate()
            .map(|(id, range)| {
                // Create an executor for the APC with the apc-free program
                let apc_executor =
                    Executor::with_context(apc_free_program.clone(), opts.clone(), context.clone());
                Apc::new(id as u64, range.len(), apc_executor)
            })
            .collect();
        Apcs { apcs }
    }

    /// Get a reference to an APC by its id.
    pub fn get_mut(&mut self, op_b: u64) -> Option<&mut Apc<'a>> {
        let index = op_b as usize;
        self.apcs.get_mut(index)
    }

    /// Iterator over the APCs.
    pub fn iter(&self) -> std::slice::Iter<'_, Apc<'a>> {
        self.apcs.iter()
    }
}
