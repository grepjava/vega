#!/usr/bin/env bash
# Build every Vega library for the iOS, tvOS, watchOS and visionOS
# simulators, and with --test run the test suite on an iOS simulator, where
# TCP defaults to Network.framework (IOBackend.network). Needs Xcode with the
# simulator SDKs, and for --test an iOS simulator runtime at the package's
# minimum (26.4).
#   Tests/apple-simulators.sh [--test] [--device "iPhone 17"] [--only Suite,Suite]
set -euo pipefail
TEST=0
DEVICE="iPhone 17"
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
    --test) TEST=1; shift ;;
    --device) DEVICE=$2; shift 2 ;;
    --only) ONLY=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 1 ;;
    esac
done

cd "$(dirname "$0")/.."
DD=${TMPDIR:-/tmp}/vega-apple-simulators
status=0
for platform in "iOS Simulator" "tvOS Simulator" "watchOS Simulator" "visionOS Simulator"; do
    if xcodebuild -scheme Vega-Package -destination "generic/platform=$platform" -derivedDataPath "$DD" \
        build >"$DD.log" 2>&1; then
        echo "build $platform: ok"
    else
        echo "build $platform: FAILED"
        grep -E "error:" "$DD.log" | sort -u | head -20
        status=1
    fi
done

if [ $TEST = 1 ]; then
    only=()
    IFS=, read -ra suites <<<"$ONLY"
    for s in "${suites[@]}"; do only+=("-only-testing:VegaTests/$s"); done
    if xcodebuild test -scheme Vega-Package -destination "platform=iOS Simulator,name=$DEVICE" \
        -derivedDataPath "$DD" "${only[@]}" >"$DD.log" 2>&1; then
        echo "test on $DEVICE: $(grep -aE 'Test run with' "$DD.log" | tail -1)"
    else
        echo "test on $DEVICE: FAILED"
        grep -aE "✘ Test .*recorded|Test run with|error:" "$DD.log" | sort -u | head -30
        status=1
    fi
fi
exit $status
