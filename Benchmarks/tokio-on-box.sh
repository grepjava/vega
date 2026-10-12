#!/usr/bin/env bash
# Copy tokio-bench to the bench box, build it there with cargo, and run it.
# Extra args go to tokio-bench.
set -euo pipefail
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
cd "$(dirname "$0")"
ssh -i $KEY -o BatchMode=yes $BOX 'mkdir -p ~/vega-run/tokio-bench/src'
scp -q -i $KEY -o BatchMode=yes tokio-bench/Cargo.toml $BOX:vega-run/tokio-bench/
scp -q -i $KEY -o BatchMode=yes tokio-bench/src/main.rs $BOX:vega-run/tokio-bench/src/
ssh -i $KEY -o BatchMode=yes $BOX "cd ~/vega-run/tokio-bench && cargo build --release -q 2>&1 | tail -5 && ./target/release/tokio-bench $*"
