#!/usr/bin/env bash
# Ship the Vega Phase-0 spike binaries + Swift runtime libs to the bench box and run them there.
set -euo pipefail
BOX=grepjava@192.168.100.100
SSH="ssh -i $HOME/.ssh/garuda_bench -o BatchMode=yes -o ConnectTimeout=10"
LIBS=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/lib/swift/linux
cd ~/vega-spike

stage=$(mktemp -d ~/vega-ship.XXXX)
mkdir -p "$stage/lib"
cp .build/release/spike .build/release/spikefactory "$stage/"
# every libswift*/dispatch/Blocks .so the binaries actually link
for b in spike spikefactory; do
  ldd ".build/release/$b" | awk '/=>/ {print $3}' | grep -E "$LIBS" || true
done | sort -u | xargs -r -I{} cp -L {} "$stage/lib/"
ls "$stage/lib"

$SSH $BOX 'mkdir -p ~/vega-run/lib'
scp -q -i $HOME/.ssh/garuda_bench -o BatchMode=yes "$stage"/spike "$stage"/spikefactory $BOX:vega-run/
scp -q -i $HOME/.ssh/garuda_bench -o BatchMode=yes "$stage"/lib/* $BOX:vega-run/lib/
rm -rf "$stage"

$SSH $BOX 'cd ~/vega-run && export LD_LIBRARY_PATH=$HOME/vega-run/lib \
  && echo "host: $(nproc --all) cpus, $(uname -r), load: $(cut -d" " -f1-3 /proc/loadavg)" \
  && pgrep -fa "garuda|peregrine|zrk|oha|server" | grep -v pgrep || echo "no other bench processes" \
  && echo && timeout 120 ./spike && echo && timeout 120 ./spikefactory --explicit'
