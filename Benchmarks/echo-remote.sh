#!/usr/bin/env bash
# The box side of echo-on-box.sh: build tokio-bench, then run each server
# against echo-load. Args: secs, connection counts, servers.
set -uo pipefail
SECS=$1 CONNS=$2 SERVERS=$3
cd ~/vega-run
ulimit -n "$(ulimit -Hn)" # 1024 connections need more than the default 1024 fds
(cd tokio-bench && cargo build --release -q 2>&1 | tail -5)
echo "host: $(nproc --all) cpus, $(uname -r), load $(cut -d' ' -f1-3 /proc/loadavg)"
pgrep -fa 'garuda|peregrine|zrk|oha|wrk' | grep -v pgrep || true
pkill -x vega-echo || true; pkill -x nio-echo || true; pkill -x echo-server || true

PORT=7000
start() {
    case "$1" in
    vega) LD_LIBRARY_PATH=$PWD/lib exec taskset -c 0,1,4,5 ./vega-echo --port $PORT --workers 4 --stats ;;
    vega-uring) VEGA_DRIVER=uring LD_LIBRARY_PATH=$PWD/lib exec taskset -c 0,1,4,5 ./vega-echo --port $PORT --workers 4 --stats ;;
    vega-patched) LD_LIBRARY_PATH=$PWD/lib-patched:$PWD/lib exec taskset -c 0,1,4,5 ./vega-echo --port $PORT --workers 4 --stats ;;
    nio) LD_LIBRARY_PATH=$PWD/lib exec taskset -c 0,1,4,5 ./nio-echo --port $PORT --workers 4 ;;
    tokio) exec taskset -c 0,1,4,5 ./tokio-bench/target/release/echo-server --port $PORT --workers 4 ;;
    esac
}

for s in $SERVERS; do
    # stdin is this script (ssh bash -s): keep the server off it
    start "$s" </dev/null >/tmp/echo-server.log 2>&1 &
    pid=$!
    for _ in $(seq 50); do
        (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
        sleep 0.1
    done
    echo "== $s"
    for c in $CONNS; do
        taskset -c 2,3,6,7 ./tokio-bench/target/release/echo-load \
            --addr 127.0.0.1:$PORT --conns "$c" --size 64 --secs "$SECS" --warmup 2 --threads 4 </dev/null
    done
    case "$s" in vega*) grep '^jobs' /tmp/echo-server.log | tail -n 3 ;; esac
    kill $pid; wait $pid 2>/dev/null || true
    PORT=$((PORT + 1)) # skip TIME_WAIT leftovers
done
