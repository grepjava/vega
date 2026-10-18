#!/usr/bin/env bash
# ci/macos.sh [macos|ios]...: Vega's Apple CI, on a Mac with Xcode 26.4 or
# later. Run from the source tree.
#   macos  swift test on kqueue (OpenSSL from Homebrew's openssl@3)
#   ios    xcodebuild test on the newest iPhone simulator (Network.framework)
#   nio    VegaNIO's own tests (VegaNIO/), on kqueue
# Logs go to .build-ci/<job>.log; exits non-zero if a job fails. A job
# that runs past its limit (VEGA_CI_LIMIT seconds, 40 minutes by default)
# is killed and fails: a hung test can't stall the run.
set -u
cd "$(dirname "$0")/.."
JOBS=("$@")
[ ${#JOBS[@]} -eq 0 ] && JOBS=(macos ios nio)
mkdir -p .build-ci
echo "$(sw_vers -productVersion), $(swift --version 2>&1 | head -1), $(git rev-parse --short HEAD)"

LIMIT=${VEGA_CI_LIMIT:-2400}

# Runs "$@" with a wall-clock limit (macOS has no timeout(1)); 124 when
# it was killed.
limited() {
  local mark=.build-ci/killed.$$
  rm -f "$mark"
  "$@" &
  local pid=$!
  ( sleep "$LIMIT"; touch "$mark"; kill -TERM "$pid" 2>/dev/null; sleep 10; kill -KILL "$pid" 2>/dev/null ) &
  local watchdog=$!
  wait "$pid"
  local code=$?
  pkill -P "$watchdog" 2>/dev/null
  kill "$watchdog" 2>/dev/null
  wait "$watchdog" 2>/dev/null
  [ -e "$mark" ] && { rm -f "$mark"; code=124; }
  return $code
}

failed=0
for job in "${JOBS[@]}"; do
  log=.build-ci/$job.log
  start=$(date +%s)
  case $job in
    macos)
      export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
      { swift build --build-tests --scratch-path .build-ci/macos &&
        limited swift test --skip-build --scratch-path .build-ci/macos; } > "$log" 2>&1 ;;
    nio)
      export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
      { swift build --build-tests --package-path VegaNIO --scratch-path .build-ci/nio &&
        limited swift test --skip-build --package-path VegaNIO --scratch-path .build-ci/nio; } > "$log" 2>&1 ;;
    ios)
      sim=$(xcrun simctl list devices available iOS | grep -oE 'iPhone [0-9]+( Pro)?' | sort -V | tail -1)
      limited xcodebuild test -scheme Vega-Package -destination "platform=iOS Simulator,name=$sim" \
        -derivedDataPath .build-ci/ios -skipPackagePluginValidation > "$log" 2>&1 ;;
    *) echo "unknown job $job"; exit 2 ;;
  esac
  code=$?
  took=$(( $(date +%s) - start ))
  summary=$(grep -E "Test run with|TEST (SUCCEEDED|FAILED)|error:" "$log" | tail -1)
  [ $code -eq 124 ] && summary="killed after ${LIMIT}s, a test hung; last lines:"
  if [ $code -eq 0 ]; then
    echo "PASS  $job (${took}s) $summary"
  else
    failed=1
    echo "FAIL  $job (${took}s, exit $code) $summary"
    if [ $code -eq 124 ]; then tail -5 "$log"; else grep -E "✘|error:" "$log" | head -20; fi | sed 's/^/      /'
  fi
done
exit $failed
