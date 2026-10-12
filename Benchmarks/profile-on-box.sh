#!/usr/bin/env bash
# Build vega-bench, ship it to the bench box and profile one benchmark with
# perf. Prints the hottest symbols (self time) and the hottest call chains.
#   wsl -d Ubuntu -e bash -l /mnt/d/code/vega/Benchmarks/profile-on-box.sh spawn_many [--global]
set -euo pipefail
BENCH=${1:?usage: profile-on-box.sh <bench> [vega-bench args...]}
shift
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
LIBS=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/lib/swift/linux
BUILD=$HOME/.cache/vega-bench-build

cd "$(dirname "$0")"
swift build -c release --scratch-path "$BUILD" 2>&1 | grep -E 'error|Build complete'
bin=$BUILD/release/vega-bench
$SSH $BOX 'mkdir -p ~/vega-run/lib'
scp -q -i $KEY -o BatchMode=yes "$bin" $BOX:vega-run/
ldd "$bin" | awk '/=>/ {print $3}' | grep -E "^$LIBS" | while read -r lib; do
  scp -q -i $KEY -o BatchMode=yes "$lib" $BOX:vega-run/lib/
done

$SSH $BOX "cd ~/vega-run && export LD_LIBRARY_PATH=\$HOME/vega-run/lib \
  && sudo perf record -q -g -F 4999 -o perf.data env LD_LIBRARY_PATH=\$HOME/vega-run/lib ./vega-bench --only $BENCH --runs 15 $* \
  && echo '--- by library ---' \
  && sudo perf report -i perf.data --no-children --sort dso --stdio -g none 2>/dev/null \
     | grep -v '^#' | grep -v '^\$' | head -12 \
  && echo '--- by symbol ---' \
  && sudo perf report -i perf.data --no-children --sort dso,sym --percent-limit 0.7 --stdio -g none 2>/dev/null \
     | grep -v '^#' | grep -v '^\$' | cut -c1-160 | head -50"
