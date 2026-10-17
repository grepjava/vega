#!/usr/bin/env bash
# ci/macos.sh [macos|ios]...: Vega's Apple CI, on a Mac with Xcode 26.4 or
# later. Run from the source tree.
#   macos  swift test on kqueue (OpenSSL from Homebrew's openssl@3)
#   ios    xcodebuild test on the newest iPhone simulator (Network.framework)
# Logs go to .build-ci/<job>.log; exits non-zero if a job fails.
set -u
cd "$(dirname "$0")/.."
JOBS=("$@")
[ ${#JOBS[@]} -eq 0 ] && JOBS=(macos ios)
mkdir -p .build-ci
echo "$(sw_vers -productVersion), $(swift --version 2>&1 | head -1), $(git rev-parse --short HEAD)"

failed=0
for job in "${JOBS[@]}"; do
  log=.build-ci/$job.log
  start=$(date +%s)
  case $job in
    macos)
      export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"
      { swift build --build-tests --scratch-path .build-ci/macos &&
        swift test --skip-build --scratch-path .build-ci/macos; } > "$log" 2>&1 ;;
    ios)
      sim=$(xcrun simctl list devices available iOS | grep -oE 'iPhone [0-9]+( Pro)?' | sort -V | tail -1)
      xcodebuild test -scheme Vega-Package -destination "platform=iOS Simulator,name=$sim" \
        -derivedDataPath .build-ci/ios -skipPackagePluginValidation > "$log" 2>&1 ;;
    *) echo "unknown job $job"; exit 2 ;;
  esac
  code=$?
  took=$(( $(date +%s) - start ))
  summary=$(grep -E "Test run with|TEST (SUCCEEDED|FAILED)|error:" "$log" | tail -1)
  if [ $code -eq 0 ]; then
    echo "PASS  $job (${took}s) $summary"
  else
    failed=1
    echo "FAIL  $job (${took}s, exit $code) $summary"
    grep -E "✘|error:" "$log" | head -20 | sed 's/^/      /'
  fi
done
exit $failed
