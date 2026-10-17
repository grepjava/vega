#!/usr/bin/env bash
# ci/linux.sh [job...]: Vega's Linux CI, on a host with Docker. Run from the
# source tree. Jobs (all by default):
#   uring     io_uring, OpenSSL
#   epoll     epoll, OpenSSL
#   boringssl io_uring, BoringSSL
#   tsan      ThreadSanitizer, io_uring (reported, not yet required)
# Docker's default seccomp profile blocks io_uring, so containers run
# unconfined. Each job builds in its own .build-ci/<job>, kept between runs.
# Logs go to .build-ci/<job>.log; exits non-zero if a required job fails.
set -u
cd "$(dirname "$0")/.."
JOBS=("$@")
[ ${#JOBS[@]} -eq 0 ] && JOBS=(uring epoll boringssl tsan)
IMAGE=vega-ci
JOBS_ARG=${CI_JOBS:-$(( $(nproc) > 2 ? $(nproc) - 2 : 1 ))}

docker image inspect $IMAGE >/dev/null 2>&1 || docker build -q -t $IMAGE ci >/dev/null || exit 2
mkdir -p .build-ci
echo "kernel $(uname -r), $(git rev-parse --short HEAD 2>/dev/null || cat .ci-commit 2>/dev/null)"

failed=0
for job in "${JOBS[@]}"; do
  driver=uring traits=OpenSSL extra= required=1
  case $job in
    uring) ;;
    epoll) driver=epoll ;;
    boringssl) traits=BoringSSL ;;
    tsan) extra=--sanitize=thread required=0 ;;
    *) echo "unknown job $job"; exit 2 ;;
  esac
  log=.build-ci/$job.log
  start=$(date +%s)
  docker run --rm --name vega-ci-$job --security-opt seccomp=unconfined \
    -v "$PWD":/src -w /src -e VEGA_DRIVER=$driver $IMAGE bash -c "
      swift build --build-tests -j $JOBS_ARG --scratch-path .build-ci/$job --traits $traits $extra &&
      swift test --skip-build --scratch-path .build-ci/$job --traits $traits $extra" > "$log" 2>&1
  code=$?
  took=$(( $(date +%s) - start ))
  summary=$(grep -E "Test run with|error:" "$log" | tail -1)
  if [ $code -eq 0 ]; then
    echo "PASS  $job (${took}s) $summary"
  else
    [ $required -eq 1 ] && failed=1
    echo "FAIL  $job (${took}s, exit $code$([ $required -eq 0 ] && echo ", not required")) $summary"
    grep -E "✘|error:" "$log" | head -20 | sed 's/^/      /'
  fi
done
exit $failed
