#!/usr/bin/env bash
# ci/conformance.sh [h2spec] [autobahn] [h3]: the protocol conformance suites,
# on a Linux host with Docker, from the source tree (ci/run.ps1 -Conformance
# sends it to the box). Both by default.
#   h2spec    HTTP/2 (RFC 9113, RFC 7541) against vega-conformance h2
#   autobahn  WebSocket (RFC 6455, RFC 7692) against vega-conformance ws,
#             with Autobahn|Testsuite's fuzzingclient
#   h3        HTTP/3 both ways with aioquic: its client against
#             vega-conformance h3, and vega-conformance h3get against its
#             server (ci/h3interop.py)
# Reports go to .build-ci/h2spec.xml and .build-ci/autobahn/; exits
# non-zero if either suite fails a case.
set -u
cd "$(dirname "$0")/.."
SUITES=("$@")
[ ${#SUITES[@]} -eq 0 ] && SUITES=(h2spec autobahn h3)
IMAGE=vega-ci:2
JOBS=${CI_JOBS:-$(( $(nproc) > 2 ? $(nproc) - 2 : 1 ))}
H2SPEC_VERSION=2.6.0
docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE ci >/dev/null || exit 2
mkdir -p .build-ci/tools .build-ci/autobahn

echo "building vega-conformance"
docker run --rm -v "$PWD":/src -w /src $IMAGE \
  swift build -c release -j $JOBS --scratch-path .build-ci/conformance --product vega-conformance \
  > .build-ci/conformance-build.log 2>&1 || { tail -20 .build-ci/conformance-build.log; exit 2; }
BIN=.build-ci/conformance/release/vega-conformance

# A server in the CI image on the host's network; stopped on exit.
serve() {
  docker run -d --rm --name vega-conformance-$1 --network host -v "$PWD":/src -w /src $IMAGE $BIN $1 $2 >/dev/null
  for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$2) 2>/dev/null && return 0; sleep 0.1; done
  echo "vega-conformance $1 did not start"; docker logs vega-conformance-$1; return 1
}
trap 'docker rm -f vega-conformance-h2 vega-conformance-ws >/dev/null 2>&1' EXIT

failed=0
for suite in "${SUITES[@]}"; do
  case $suite in
    h2spec)
      if [ ! -x .build-ci/tools/h2spec ]; then
        curl -sSL https://github.com/summerwind/h2spec/releases/download/v$H2SPEC_VERSION/h2spec_linux_amd64.tar.gz \
          | tar -xz -C .build-ci/tools h2spec || exit 2
      fi
      serve h2 8081 || exit 2
      .build-ci/tools/h2spec -h 127.0.0.1 -p 8081 -o 5 -j .build-ci/h2spec.xml > .build-ci/h2spec.log 2>&1
      code=$?
      summary=$(grep -E "^[0-9]+ tests, [0-9]+ passed" .build-ci/h2spec.log | tail -1)
      if [ $code -eq 0 ]; then echo "PASS  h2spec: $summary"; else
        failed=1; echo "FAIL  h2spec: $summary"
        grep -B2 -A6 -E "×" .build-ci/h2spec.log | head -60 | sed 's/^/      /'
      fi
      docker rm -f vega-conformance-h2 >/dev/null ;;
    autobahn)
      serve ws 9001 || exit 2
      rm -rf .build-ci/autobahn/*
      docker run --rm --network host -v "$PWD/ci/autobahn":/config -v "$PWD/.build-ci/autobahn":/reports \
        crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json \
        > .build-ci/autobahn.log 2>&1
      # Each case's behavior: OK, NON-STRICT and INFORMATIONAL pass.
      result=$(python3 - <<'PY'
import json
r = json.load(open(".build-ci/autobahn/index.json"))["vega"]
bad = {k: v["behavior"] for k, v in r.items() if v["behavior"] not in ("OK", "NON-STRICT", "INFORMATIONAL")}
print(f"{len(r) - len(bad)}/{len(r)} cases pass")
for k in sorted(bad, key=lambda s: [int(x) for x in s.split(".")])[:40]: print(f"      {k}: {bad[k]}")
PY
)
      if echo "$result" | head -1 | awk -F'[/ ]' '{exit !($1 == $2)}'; then echo "PASS  autobahn: $result"; else
        failed=1; echo "FAIL  autobahn: $result"
      fi
      docker rm -f vega-conformance-ws >/dev/null ;;
    h3)
      docker run --rm --network host -v "$PWD":/src -w /src $IMAGE python3 ci/h3interop.py $BIN         > .build-ci/h3interop.log 2>&1
      code=$?
      summary=$(tail -1 .build-ci/h3interop.log)
      if [ $code -eq 0 ]; then echo "PASS  h3 interop: $summary"; else
        failed=1; echo "FAIL  h3 interop: $summary"
        grep -E "FAIL|Error|error" .build-ci/h3interop.log | head -20 | sed 's/^/      /'
      fi ;;
    *) echo "unknown suite $suite"; exit 2 ;;
  esac
done
exit $failed
