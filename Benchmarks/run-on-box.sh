#!/usr/bin/env bash
# Build vega-bench in WSL, ship it with the Swift runtime libs to the bench box
# (192.168.100.100) and run it there in both modes. Extra args go to vega-bench.
#   wsl -d Ubuntu -e bash -l /mnt/d/code/vega/Benchmarks/run-on-box.sh --runs 9
set -euo pipefail
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
LIBS=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/lib/swift/linux
BUILD=$HOME/.cache/vega-bench-build

cd "$(dirname "$0")"
swift build -c release --scratch-path "$BUILD" 2>&1 | grep -E 'error|Build complete'
bin=$BUILD/release/vega-bench

stage=$(mktemp -d ~/vega-ship.XXXX)
mkdir -p "$stage/lib"
cp "$bin" "$stage/"
ldd "$bin" | awk '/=>/ {print $3}' | grep -E "^$LIBS" | xargs -r -I{} cp -L {} "$stage/lib/"
$SSH $BOX 'mkdir -p ~/vega-run/lib'
scp -q -i $KEY -o BatchMode=yes "$stage/vega-bench" $BOX:vega-run/
scp -q -i $KEY -o BatchMode=yes "$stage"/lib/* $BOX:vega-run/lib/
rm -rf "$stage"

$SSH $BOX "cd ~/vega-run && export LD_LIBRARY_PATH=\$HOME/vega-run/lib \
  && echo \"host: \$(nproc --all) cpus, \$(uname -r), load \$(cut -d' ' -f1-3 /proc/loadavg)\" \
  && (pgrep -fa 'garuda|peregrine|zrk|oha|wrk' | grep -v pgrep || true) \
  && ./vega-bench $* && echo && ./vega-bench --global $*"
