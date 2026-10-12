#!/usr/bin/env bash
# Make a copy of the installed Swift toolchain that carries Vega's patched
# concurrency runtime, so apps build against it like any toolchain:
#
#   runtime/make-toolchain-linux.sh [DEST]      # default ~/.local/share/vega-swift-6.3.3
#   DEST/usr/bin/swift build -c release -Xswiftc -static-stdlib
#
# The copy is hard-linked (instant, no extra space) except for the two
# replaced files: libswift_Concurrency.so (dynamic linking) and
# libswift_Concurrency.a (-static-stdlib). Statically linked binaries carry
# the patched runtime inside them and need nothing shipped alongside; they
# are also the fastest, since the runtime's thread-locals become direct
# accesses. Builds both libraries first if runtime/out lacks them.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

resources=$(swiftc -print-target-info | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["runtimeResourcePath"])')
TC=${resources%/usr/lib/swift}
version=$(swiftc --version 2>&1 | head -1 | sed -E 's/.*Swift version ([0-9.]+).*/\1/')
DEST=${1:-$HOME/.local/share/vega-swift-$version}

so=$HERE/out/patched-shared/libswift_Concurrency.so
a=$HERE/out/patched-static/libswift_Concurrency.a
[ -f "$so" ] || "$HERE/build-linux.sh"
[ -f "$a" ] || "$HERE/build-linux.sh" --static

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -al "$TC" "$DEST"
# Replace, never write through, the hard links.
for pair in "$so:usr/lib/swift/linux/libswift_Concurrency.so" \
            "$a:usr/lib/swift_static/linux/libswift_Concurrency.a"; do
  src=${pair%%:*} dst=$DEST/${pair#*:}
  rm "$dst"
  cp "$src" "$dst"
done
echo "patched toolchain: $DEST/usr/bin (Swift $version)"
