#!/usr/bin/env bash
# UDP echo packets-per-second on the bench box: Vega (one datagram per
# syscall, mmsg batches, GSO/GRO; epoll and io_uring) against Tokio, all
# driven by tokio-bench's udp-load (sendmmsg/recvmmsg, a window in flight
# per flow).
#
# The server gets physical cores 0-1 (CPUs 0,1,4,5) and 4 workers; the load
# generator gets cores 2-3 (CPUs 2,3,6,7). Run from WSL:
#   wsl -d Ubuntu -e bash -l /mnt/d/code/vega/Benchmarks/udp-on-box.sh [--secs 10] [--flows "1 4"] [--sizes "64 1200"]
set -euo pipefail
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
SSH="ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=10"
LIBS=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/lib/swift/linux
SECS=10
FLOWS="1 4"
SIZES="64 1200"
SERVERS="vega-single vega-batch vega-gso vega-uring-single vega-uring-batch tokio"
while [ $# -gt 0 ]; do
    case "$1" in
    --secs) SECS=$2; shift 2 ;;
    --flows) FLOWS=$2; shift 2 ;;
    --sizes) SIZES=$2; shift 2 ;;
    --servers) SERVERS=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
swift build -c release --scratch-path "$HOME/.cache/vega-bench-build" --product vega-udp 2>&1 | grep -E 'error|complete'
vega=$HOME/.cache/vega-bench-build/release/vega-udp

stage=$(mktemp -d ~/vega-ship.XXXX)
mkdir -p "$stage/lib"
cp "$vega" "$stage/"
ldd "$vega" | awk '/=>/ {print $3}' | grep -E "^$LIBS" | xargs -r -I{} cp -L {} "$stage/lib/"
$SSH $BOX 'pkill -x vega-udp; pkill -x udp-echo; mkdir -p ~/vega-run/lib ~/vega-run/tokio-bench/src/bin; true'
scp -q -i $KEY -o BatchMode=yes "$stage/vega-udp" $BOX:vega-run/
scp -q -i $KEY -o BatchMode=yes "$stage"/lib/* $BOX:vega-run/lib/
rm -rf "$stage"
scp -q -i $KEY -o BatchMode=yes tokio-bench/Cargo.toml $BOX:vega-run/tokio-bench/
scp -q -i $KEY -o BatchMode=yes tokio-bench/src/main.rs $BOX:vega-run/tokio-bench/src/
scp -q -i $KEY -o BatchMode=yes tokio-bench/src/bin/*.rs $BOX:vega-run/tokio-bench/src/bin/

scp -q -i $KEY -o BatchMode=yes udp-remote.sh $BOX:vega-run/
$SSH $BOX "bash ${TRACE:+-x} ~/vega-run/udp-remote.sh '$SECS' '$FLOWS' '$SIZES' '$SERVERS'"
