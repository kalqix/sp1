#![no_main]
sp1_zkvm::entrypoint!(main);

use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    let num_cases = sp1_zkvm::io::read::<usize>();
    for _ in 0..num_cases {
        // TODO: read input from stdin
        let input = [0u8]; // Test the same input for each hash
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        sp1_zkvm::io::commit(&output);
    }
}
