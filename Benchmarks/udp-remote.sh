#!/usr/bin/env bash
# The box side of udp-on-box.sh: build tokio-bench, then run each server
# against udp-load. Args: secs, flow counts, payload sizes, servers.
set -uo pipefail
SECS=$1 FLOWS=$2 SIZES=$3 SERVERS=$4
cd ~/vega-run
(cd tokio-bench && cargo build --release -q 2>&1 | tail -5)
echo "host: $(nproc --all) cpus, $(uname -r), load $(cut -d' ' -f1-3 /proc/loadavg)"
pgrep -fa 'garuda|peregrine|zrk|oha|wrk' | grep -v pgrep || true
pkill -x vega-udp || true; pkill -x udp-echo || true

PORT=7100
start() {
    local lib="LD_LIBRARY_PATH=$PWD/lib"
    case "$1" in
    vega-single) exec env $lib VEGA_DRIVER=epoll taskset -c 0,1,4,5 ./vega-udp --port $PORT --workers 4 --mode single ;;
    vega-batch) exec env $lib VEGA_DRIVER=epoll taskset -c 0,1,4,5 ./vega-udp --port $PORT --workers 4 --mode batch ;;
    vega-gso) exec env $lib VEGA_DRIVER=epoll taskset -c 0,1,4,5 ./vega-udp --port $PORT --workers 4 --mode gso ;;
    vega-uring-single) exec env $lib VEGA_DRIVER=uring taskset -c 0,1,4,5 ./vega-udp --port $PORT --workers 4 --mode single ;;
    vega-uring-batch) exec env $lib VEGA_DRIVER=uring taskset -c 0,1,4,5 ./vega-udp --port $PORT --workers 4 --mode batch ;;
    tokio) exec taskset -c 0,1,4,5 ./tokio-bench/target/release/udp-echo --port $PORT --workers 4 ;;
    esac
}

for s in $SERVERS; do
    start "$s" </dev/null >/tmp/udp-server.log 2>&1 &
    pid=$!
    sleep 1
    echo "== $s"
    for f in $FLOWS; do
        for z in $SIZES; do
            taskset -c 2,3,6,7 ./tokio-bench/target/release/udp-load \
                --addr 127.0.0.1:$PORT --ports 4 --flows "$f" --size "$z" --secs "$SECS" --warmup 2 </dev/null
        done
    done
    grep -v '^vega-udp: [a-z]* on' /tmp/udp-server.log | head -3
    kill $pid; wait $pid 2>/dev/null || true
    PORT=$((PORT + 10)) # each server takes PORT..PORT+3
done
