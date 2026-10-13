#!/usr/bin/env bash
# Builds vega-https against BoringSSL instead of the system's OpenSSL, for
# comparing the two under the same server. VegaTLS itself stays on OpenSSL:
# this copies the repository to a scratch directory, drops in aviancore's
# vendored BoringSSL (CAvianSSL, symbols prefixed) and points CVegaTLS at it.
# Run in WSL or on Linux:
#   bash Benchmarks/tls-boringssl.sh [/path/to/aviancore]
# The binary lands in $HOME/.cache/vega-boring-build/release/vega-https.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
avian=${1:-$here/../aviancore}
copy=$HOME/vega-boring/vega # SwiftPM names a path dependency after its directory

mkdir -p "$copy"
rsync -a --delete --exclude .build --exclude .git --exclude .deps --exclude VegaNIO \
    --exclude 'Benchmarks/tokio-bench/target' "$here/" "$copy/"
rsync -a --delete "$avian/Sources/CAvianSSL/" "$copy/Sources/CAvianSSL/"

python3 - "$copy/Package.swift" <<'EOF'
import re, sys
path = sys.argv[1]
s = open(path, encoding="utf-8").read()
start = s.index('        .systemLibrary(name: "COpenSSL"')
end = s.index('        .target(name: "VegaTLS"')
s = s[:start] + '''        .target(name: "CAvianSSL", cSettings: [.define("_GNU_SOURCE"), .define("_POSIX_C_SOURCE", to: "200112L")]),
        .target(name: "CVegaTLS", dependencies: ["CAvianSSL"], cSettings: [.define("VEGA_TLS_BORINGSSL")]),
''' + s[end:]
open(path, "w", encoding="utf-8").write(s)
EOF

cd "$copy/Benchmarks"
swift build -c release --scratch-path "$HOME/.cache/vega-boring-build" --product vega-https 2>&1 \
    | grep -E 'error|warning: implicit|Compiling|Build' | grep -v '^\[' | tail -30
