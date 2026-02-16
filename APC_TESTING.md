# APC GPU Testing Guide

## Build & Install GPU Server

```bash
cd sp1-gpu
cargo build --release -p sp1-gpu-server
cp target/release/sp1-gpu-server ~/.sp1/bin/sp1-gpu-server
```

## Run Tests

### GPU

```bash
SP1_PROVER=cuda RUST_BACKTRACE=1 RUST_LOG=debug cargo test -r -p sp1-sdk --features native-gnark,experimental,profiling,slow-tests test_apc_core_keccak_200 -- --nocapture
```

### CPU

```bash
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -r -p sp1-sdk --features native-gnark,experimental,profiling,slow-tests test_apc_core_keccak_200 -- --nocapture
```
