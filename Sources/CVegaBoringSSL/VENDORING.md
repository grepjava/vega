# CVegaBoringSSL — a vendored BoringSSL

This directory is BoringSSL, and none of it is ours. VegaTLS runs on the
system's OpenSSL by default; the package trait `BoringSSL` builds it on this
copy instead. Through vega-https on the bench box, BoringSSL completed 1.35×
OpenSSL 3.5's handshakes on the same key exchange, at 20% less server CPU per
connection, and spent 3–11% less per request on kept-alive connections
(docs/BENCHMARKS.md, "TLS: OpenSSL against BoringSSL").

## Where it came from

From aviancore's `Sources/CAvianSSL` (0.7.3), which is itself **swift-nio-ssl's**
vendored copy, pre-generated and patched for SwiftPM: no CMake, no Go, no build
step of its own. `hash.txt` records the BoringSSL revision, and `LICENSE.txt`
and `NOTICE.txt` are carried with it.

    swift-nio-ssl 2.37.4
    BoringSSL     817ab07ebb53da35afea409ab9328f578492832d

## Why the symbols say CVegaBoringSSL

BoringSSL's public names are prefixed so they cannot collide with a system
OpenSSL, nor with another BoringSSL in the same binary. swift-nio-ssl's copy is
prefixed `CNIOBoringSSL` and aviancore's `CAvianSSL`. An application using Vega
alongside either (Vapor or Hummingbird with TLS through VegaNIO, or Garuda on
aviancore) would otherwise link two BoringSSL versions under one set of names
and get whichever the linker picked. With its own prefix this copy coexists
with both.

The prefix is not baked into the sources. They are stock BoringSSL, and every
public name is redirected by `BORINGSSL_ADD_PREFIX` macros in
`include/CVegaBoringSSL_boringssl_prefix_symbols.h` against one line in
`include/CVegaBoringSSL_base.h`:

    #define BORINGSSL_PREFIX CVegaBoringSSL

The prefix list misses a few wrapper functions. `Sources/CVegaTLS/cvega_tls.c`
works around the one it needs (`X509V3_EXT_conf_nid`).

## Updating it

Re-prefixing is textual, because the sources are unmodified. Take
swift-nio-ssl's `Sources/CNIOBoringSSL` at the release wanted, then rename the
files and rewrite the references:

```bash
rm -rf Sources/CVegaBoringSSL.new
cp -a <swift-nio-ssl>/Sources/CNIOBoringSSL Sources/CVegaBoringSSL.new
cd Sources/CVegaBoringSSL.new
find . -depth -name '*CNIOBoringSSL*' | while read f; do
    mv "$f" "$(dirname "$f")/$(basename "$f" | sed 's/CNIOBoringSSL/CVegaBoringSSL/')"
done
grep -rlI CNIOBoringSSL . | xargs sed -i 's/CNIOBoringSSL/CVegaBoringSSL/g'
```

Then check that nothing is left (`grep -rI CNIOBoringSSL .`), that
`CVegaBoringSSL_base.h` still defines `BORINGSSL_PREFIX` as `CVegaBoringSSL`,
carry this file across, replace the old directory, and run the TLS tests with
the trait on:

    swift test --traits BoringSSL --filter 'TLS|Interop'

**This directory is a security dependency.** Vendoring means Vega, not a
distribution, decides when a BoringSSL fix reaches anyone who builds with the
`BoringSSL` trait. Track upstream (or swift-nio-ssl's releases) and take fixes
promptly. A package that depends on Vega without the trait never compiles this
directory; building Vega itself compiles it, as it does every target.
