#!/usr/bin/env bash
# Does a Vega timer depend on Swift's default cooperative pool? Hold that pool's
# threads with plain usleep tests (VEGA_BLOCKERS) and time a Vega sleep alongside.
cd "$(dirname "$0")/.."
swift build --build-tests --scratch-path ~/.cache/vega-build 2>&1 | grep -E 'error|Build complete'
for t in sleepsWakeInOrderAndOnTime timersFireWhileWorkersAreBusy; do
  echo "== $t + cooperative-pool blockers"
  VEGA_BLOCKERS=1 timeout 60 swift test --skip-build --scratch-path ~/.cache/vega-build \
    --filter "$t|holdCooperativeThread" 2>&1 | grep -E '✘ Test|↳ (took|sleep)|Test run'
done
