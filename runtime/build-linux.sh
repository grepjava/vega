#!/usr/bin/env bash
# Build Vega's patched Swift concurrency runtime (libswift_Concurrency) for
# Linux from the Swift release source plus runtime/patches/*.patch.
#
#   runtime/build-linux.sh [--stock] [--static] [--out DIR]
#
# Library evolution is on, as in the toolchain's own Linux build: apps are
# compiled against the toolchain's resilient interface and call its dispatch
# thunks, so the replacement must export the same symbols.
#
# Uses the installed toolchain's swiftc and clang (it must be the same
# release as SWIFT_TAG) and the standalone Runtimes/Core CMake project, so no
# compiler is built. Takes ~15 minutes on 4 cores; later runs are incremental.
#   --stock   build without the patches (baseline for benchmarks)
#   --static  build libswift_Concurrency.a (for -static-stdlib) instead of .so
#   --out     where to copy the result (default: runtime/out/<variant>)
set -euo pipefail

SWIFT_TAG=${SWIFT_TAG:-swift-6.3.3-RELEASE}
WORK=${VEGA_RT_WORK:-$HOME/.cache/vega-swift-runtime}
HERE=$(cd "$(dirname "$0")" && pwd)
PATCHED=1 SHARED=YES OUT=
while [ $# -gt 0 ]; do
  case $1 in
    --stock) PATCHED=0 ;;
    --static) SHARED=NO ;;
    --out) OUT=$2; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
variant=$([ $PATCHED = 1 ] && echo patched || echo stock)-$([ $SHARED = YES ] && echo shared || echo static)
OUT=${OUT:-$HERE/out/$variant}

SWIFTC=$(command -v swiftc)
# The toolchain's usr/ directory (swiftc may be a swiftly proxy).
resources=$("$SWIFTC" -print-target-info | python3 -c 'import json,sys; print(json.load(sys.stdin)["paths"]["runtimeResourcePath"])')
TC=${resources%/lib/swift}
want=${SWIFT_TAG#swift-}
want=${want%-RELEASE}
version=$("$SWIFTC" --version 2>&1 | head -1)
case $version in
  *"Swift version $want "*) ;;
  *) echo "toolchain is '$version', expected Swift $want" >&2; exit 1 ;;
esac

mkdir -p "$WORK"
cd "$WORK"

# Tools: CMake >= 3.29 and ninja, local to $WORK.
if [ ! -x venv/bin/cmake ] || [ ! -x venv/bin/ninja ]; then
  [ -d venv ] || python3 -m venv venv
  venv/bin/pip install -q "cmake>=3.30,<4.1" ninja
fi
export PATH=$WORK/venv/bin:$PATH

# Source: one checkout per variant so stock and patched builds don't fight.
src=$WORK/src-$([ $PATCHED = 1 ] && echo patched || echo stock)
if [ ! -d "$src" ]; then
  git clone -q --depth 1 --branch "$SWIFT_TAG" "${SWIFT_REPO:-https://github.com/swiftlang/swift.git}" "$src"
fi
git -C "$src" reset -q --hard "$SWIFT_TAG" 2>/dev/null || git -C "$src" checkout -q -- .
if [ $PATCHED = 1 ]; then
  for p in "$HERE"/patches/*.patch; do
    git -C "$src" apply --whitespace=nowarn "$p"
    echo "applied $(basename "$p")"
  done
fi
# The Runtimes/ build compiles copies of the stdlib sources.
(cd "$src/Runtimes" && cmake -P Resync.cmake >/dev/null)

build=$WORK/build-$variant
cmake -G Ninja -S "$src/Runtimes/Core" -B "$build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=$SHARED \
  -DSwiftCore_ENABLE_CONCURRENCY=ON \
  -DSwiftCore_ENABLE_LIBRARY_EVOLUTION=ON \
  -DCMAKE_C_COMPILER="$TC/bin/clang" \
  -DCMAKE_CXX_COMPILER="$TC/bin/clang++" \
  -DCMAKE_Swift_COMPILER="$TC/bin/swiftc" \
  -Ddispatch_INCLUDE_DIR="$TC/lib/swift" \
  -Ddispatch_LIBRARY="$TC/lib/swift/linux/libdispatch.so" >/dev/null
cmake --build "$build" --target swift_Concurrency

mkdir -p "$OUT"
if [ $SHARED = YES ]; then
  # ABI gate: everything the toolchain's library exports must still be
  # exported (extra symbols are fine), or apps built against the toolchain
  # fail to load against ours.
  syms() { nm -D --defined-only "$1" | awk '{print $3}' | sort -u; }
  missing=$(comm -23 <(syms "$TC/lib/swift/linux/libswift_Concurrency.so") \
                     <(syms "$build/Concurrency/libswift_Concurrency.so"))
  if [ -n "$missing" ]; then
    echo "ABI mismatch: $(echo "$missing" | wc -l) toolchain symbols missing, e.g." >&2
    echo "$missing" | head -20 >&2
    exit 1
  fi
  cp "$build/Concurrency/libswift_Concurrency.so" "$OUT/"
else
  cp "$build/Concurrency/libswift_Concurrency.a" "$OUT/"
fi
echo "built $OUT/$(ls "$OUT")"
