# CVegaZlib — a vendored zlib, for Windows

This directory is zlib, and none of it is ours. CVegaCompress (gzip and
deflate bodies in VegaCompression, permessage-deflate in VegaWebSocket) links the
system's zlib on Linux and Apple platforms, which always have one; the
Windows SDK has none, so on Windows CVegaCompress depends on this copy
instead (a target dependency with a platform condition in `Package.swift`).

Linux and macOS keep the system zlib: it is there on every machine, it gets
the distribution's security fixes, and nothing gained by building our own
there would pay for owning those updates.

## Where it came from

The official release, unmodified:

    https://zlib.net/fossils/zlib-1.3.1.tar.gz
    sha256 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

Only what deflate and inflate need is kept:

    adler32.c crc32.c deflate.c inflate.c inffast.c inftrees.c trees.c zutil.c
    crc32.h deflate.h gzguts.h inffast.h inffixed.h inflate.h inftrees.h
    trees.h zutil.h
    include/zlib.h include/zconf.h
    LICENSE README

`gzguts.h` is there because `zutil.c` includes it (for the allocator it
defines outside `Z_SOLO`); the gz* file functions themselves are not. Nor are
compress/uncompress, infback, the build files, contrib, examples or tests.

## Why the symbols are z_-prefixed

The target is built with `Z_PREFIX` defined (zconf.h's own switch), so every
public name becomes `z_deflate`, `z_inflate` and so on, and
`Sources/CVegaCompress/cvega_compress.c` defines `Z_PREFIX` before it
includes `zlib.h` on Windows. An application that links another zlib (a
static one, or one inside a library it uses) then gets two that cannot
collide, whichever the linker sees first.

## Updating it

Take the new release from zlib.net, check its signature or published hash,
and copy the same files over these (the headers `zlib.h` and `zconf.h` into
`include/`). If the release adds a source file that deflate or inflate needs,
add it here. Then build on Windows and run the compression tests:

    swift test --filter "Compression|Deflate|WebSocket"

and record the version and hash above.
