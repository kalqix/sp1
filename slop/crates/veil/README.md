# VEIL - Verifiable Encapsulation of Interactive proof with Low overhead

A proof-of-concept implementation of the VEIL protocol. See [the paper](paper/veil.pdf) for details.

> **Disclaimer:** This code is unaudited and in active development. It is not intended for production use.

## Examples

### Polynomial Root (`examples/root.rs`)
Proves knowledge of a root of a public polynomial without revealing it. This is a pure constraint-based proof with no PCS — a good starting point for understanding the VEIL interface.

```bash
cargo run --release -p slop-veil --example root
```

### MLE Evaluation (`examples/mle_eval.rs`)
Demonstrates the full prove/verify flow with polynomial commitment: commits to a random multilinear extension, evaluates it at a random point, and proves the evaluation is correct using the stacked PCS.

```bash
cargo run --release -p slop-veil --example mle_eval
```
