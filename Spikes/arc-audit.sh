#!/usr/bin/env bash
# Count ARC calls (swift_retain/release and friends) per hot function in the
# release build of the Vega module. Usage: Spikes/arc-audit.sh [pattern]
set -euo pipefail
cd "$(dirname "$0")/.."
swift build -c release --scratch-path ~/.cache/vega-build-rel 2>&1 | grep -E 'error|Build complete'
objs=$(find ~/.cache/vega-build-rel/x86_64-unknown-linux-gnu/release/Vega.build -name '*.o')
pattern=${1:-'Worker|Scheduler|LocalQueue|InjectQueue|Idle|TimerQueue'}
for o in $objs; do
  objdump -dr --no-show-raw-insn "$o"
done | swift demangle --simplified | awk -v pat="$pattern" '
  /^[0-9a-f]+ <.*>:$/ { fn = $0; sub(/^[0-9a-f]+ </, "", fn); sub(/>:$/, "", fn); next }
  /(call|R_X86_64_PLT32|R_X86_64_GOTPCRELX).*(swift_retain|swift_release|swift_bridgeObjectRetain|swift_bridgeObjectRelease|swift_unknownObject|swift_allocObject)/ {
    if (fn ~ pat) {
      what = $0; sub(/.*(R_X86_64_[A-Z0-9]+[ 	]+|<)/, "", what); sub(/(@plt|-0x4|+0x[0-9a-f]+)?>?.*$/, "", what)
      count[fn " :: " what]++
    }
  }
  END { for (k in count) printf "%4d  %s\n", count[k], k }' | sort -k2 | cut -c1-200
