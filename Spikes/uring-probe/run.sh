#!/usr/bin/env bash
# Build the io_uring probe statically in WSL, run it in WSL, on the bench box host, and in Docker there.
set -uo pipefail
here=$(dirname "$(readlink -f "$0")")
BOX=grepjava@192.168.100.100
KEY=$HOME/.ssh/garuda_bench
CC=$HOME/.local/share/swiftly/toolchains/6.3.3/usr/bin/clang
command -v gcc >/dev/null && CC=gcc
$CC -O2 -static -o ~/uring-probe "$here/probe.c" || exit 1
echo "### WSL"; ~/uring-probe
scp -q -i $KEY -o BatchMode=yes ~/uring-probe $BOX:vega-run/uring-probe
echo; echo "### bench box host"
ssh -i $KEY -o BatchMode=yes $BOX '~/vega-run/uring-probe'
echo; echo "### bench box, docker default seccomp"
ssh -i $KEY -o BatchMode=yes $BOX 'img=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -m1 -E "garuda-swift|ubuntu|swift"); echo "image: $img"; docker run --rm -v ~/vega-run/uring-probe:/p:ro "$img" /p'
echo; echo "### bench box, docker seccomp=unconfined"
ssh -i $KEY -o BatchMode=yes $BOX 'img=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -m1 -E "garuda-swift|ubuntu|swift"); docker run --rm --security-opt seccomp=unconfined -v ~/vega-run/uring-probe:/p:ro "$img" /p'
