#!/usr/bin/env bash
# TCP echo benchmark on the bench box: Vega vs SwiftNIO vs Tokio, all driven
# by the same closed-loop client (tokio-bench's echo-load).
#
# The server gets physical cores 0-1 (CPUs 0,1,4,5) and 4 workers; the load
# generator gets cores 2-3 (CPUs 2,3,6,7). Run from WSL:
#   wsl -d Ubuntu -e bash -l /mnt/d/code/vega/Benchmarks/echo-on-box.sh [--secs 10] [--conns "64 256 1024"]
set -euo pipefail
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
LIBS=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/lib/swift/linux
PATCHED=$HOME/swiftrt/out/patched/libswift_Concurrency.so
SECS=10
CONNS="64 256 1024"
SERVERS="vega vega-uring vega-patched nio tokio"
while [ $# -gt 0 ]; do
    case "$1" in
    --secs) SECS=$2; shift 2 ;;
    --conns) CONNS=$2; shift 2 ;;
    --servers) SERVERS=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
swift build -c release --scratch-path "$HOME/.cache/vega-bench-build" --product vega-echo 2>&1 | grep -E 'error|complete'
(cd nio-echo && swift build -c release --scratch-path "$HOME/.cache/nio-echo-build" 2>&1 | grep -E 'error|complete')
vega=$HOME/.cache/vega-bench-build/release/vega-echo
nio=$HOME/.cache/nio-echo-build/release/nio-echo

stage=$(mktemp -d ~/vega-ship.XXXX)
mkdir -p "$stage/lib"
cp "$vega" "$nio" "$stage/"
for b in "$vega" "$nio"; do
    ldd "$b" | awk '/=>/ {print $3}' | grep -E "^$LIBS" | xargs -r -I{} cp -L {} "$stage/lib/"
done
$SSH $BOX 'pkill -x vega-echo; pkill -x nio-echo; pkill -x echo-server; mkdir -p ~/vega-run/lib ~/vega-run/lib-patched ~/vega-run/tokio-bench/src/bin; true'
scp -q -i $KEY -o BatchMode=yes "$stage/vega-echo" "$stage/nio-echo" $BOX:vega-run/
scp -q -i $KEY -o BatchMode=yes "$stage"/lib/* $BOX:vega-run/lib/
[ -f "$PATCHED" ] && scp -q -i $KEY -o BatchMode=yes "$PATCHED" $BOX:vega-run/lib-patched/
rm -rf "$stage"
scp -q -i $KEY -o BatchMode=yes tokio-bench/Cargo.toml $BOX:vega-run/tokio-bench/
scp -q -i $KEY -o BatchMode=yes tokio-bench/src/main.rs $BOX:vega-run/tokio-bench/src/
scp -q -i $KEY -o BatchMode=yes tokio-bench/src/bin/*.rs $BOX:vega-run/tokio-bench/src/bin/

scp -q -i $KEY -o BatchMode=yes echo-remote.sh $BOX:vega-run/
$SSH $BOX "bash ${TRACE:+-x} ~/vega-run/echo-remote.sh '$SECS' '$CONNS' '$SERVERS'"
