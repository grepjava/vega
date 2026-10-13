#!/usr/bin/env bash
# TCP and UDP echo on this Mac: Vega (kqueue) vs Tokio, driven by
# tokio-bench's echo-load and udp-load. A laptop check for kqueue-specific
# regressions, not a replacement for the bench box: macOS can't pin threads,
# so server and load share all cores.
#   Benchmarks/macos-local.sh [--secs 10] [--conns "64 256 1024"]
#                             [--flows "1 4"] [--sizes "64 1200"] [--only tcp|udp]
set -euo pipefail
SECS=10
CONNS="64 256 1024"
FLOWS="1 4"
SIZES="64 1200"
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
    --secs) SECS=$2; shift 2 ;;
    --conns) CONNS=$2; shift 2 ;;
    --flows) FLOWS=$2; shift 2 ;;
    --sizes) SIZES=$2; shift 2 ;;
    --only) ONLY=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
    esac
done

cd "$(dirname "$0")"
swift build -c release --product vega-echo 2>&1 | grep -E 'error|Compiling|Build complete' | tail -1
swift build -c release --product vega-udp 2>&1 | grep -E 'error|Compiling|Build complete' | tail -1
(cd tokio-bench && cargo build --release -q 2>&1 | tail -5)
bin=$(swift build -c release --show-bin-path)
tb=tokio-bench/target/release
ulimit -n 10240 # 1024 connections need more than the default 256 fds

echo "host: $(sysctl -n machdep.cpu.brand_string), $(sysctl -n hw.ncpu) cpus" \
     "($(sysctl -n hw.perflevel0.physicalcpu)P+$(sysctl -n hw.perflevel1.physicalcpu)E)," \
     "macOS $(sw_vers -productVersion), load $(sysctl -n vm.loadavg)"

wait_tcp() {
    for _ in $(seq 50); do
        (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return
        sleep 0.1
    done
}

PORT=17000 # 7000 is AirPlay Receiver on macOS
if [ "$ONLY" != udp ]; then
    for s in vega tokio; do
        case "$s" in
        vega) "$bin/vega-echo" --port $PORT --workers 4 --stats </dev/null >/tmp/echo-server.log 2>&1 & ;;
        tokio) "$tb/echo-server" --port $PORT --workers 4 </dev/null >/tmp/echo-server.log 2>&1 & ;;
        esac
        pid=$!
        wait_tcp $PORT
        echo "== tcp $s"
        for c in $CONNS; do
            "$tb/echo-load" --addr 127.0.0.1:$PORT --conns "$c" --size 64 --secs "$SECS" --warmup 2 --threads 4 </dev/null
        done
        kill $pid; wait $pid 2>/dev/null || true
        PORT=$((PORT + 1)) # skip TIME_WAIT leftovers
    done
fi

PORT=17100
if [ "$ONLY" != tcp ]; then
    for s in vega-single vega-batch vega-gso tokio; do
        case "$s" in
        vega-*) "$bin/vega-udp" --port $PORT --workers 4 --mode "${s#vega-}" </dev/null >/tmp/udp-server.log 2>&1 & ;;
        tokio) "$tb/udp-echo" --port $PORT --workers 4 </dev/null >/tmp/udp-server.log 2>&1 & ;;
        esac
        pid=$!
        sleep 1
        echo "== udp $s"
        for f in $FLOWS; do
            for z in $SIZES; do
                "$tb/udp-load" --addr 127.0.0.1:$PORT --ports 4 --flows "$f" --size "$z" --secs "$SECS" --warmup 2 </dev/null
            done
        done
        kill $pid; wait $pid 2>/dev/null || true
        PORT=$((PORT + 10)) # each server takes PORT..PORT+3
    done
fi
