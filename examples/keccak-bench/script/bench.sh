#!/usr/bin/env bash

NUM_HASHES=$1
APCS=$2

MANUAL_FLAG=""
SUFFIX=""
if [ "$3" == "manual" ]; then
  MANUAL_FLAG="--manual"
  SUFFIX="_manual"
fi

RUST_LOG_FORMAT=json RUST_LOG=debug cargo run -r -- --num-hashes $NUM_HASHES --apcs $APCS $MANUAL_FLAG | ../../parse_logs.py > results_${NUM_HASHES}_hashes_${APCS}_apcs${SUFFIX}.csv