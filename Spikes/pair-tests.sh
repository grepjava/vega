#!/usr/bin/env bash
# Run one test alongside each other test, to find interference between parallel tests.
# usage: Spikes/pair-tests.sh <test> <other>...
cd "$(dirname "$0")/.."
target=$1; shift
for f in "$@"; do
  echo "== $target with $f"
  timeout 60 swift test --skip-build --scratch-path ~/.cache/vega-build --filter "$target|$f" 2>&1 \
    | grep -E '✘ Test|↳ (took|sleep)|Test run'
done
