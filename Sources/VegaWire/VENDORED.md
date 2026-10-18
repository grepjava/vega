# VegaWire

The bytes that Vega's sans-I/O Core modules share: `ByteBuffer`, `ByteSpan`
and the parsing helpers. Pure Swift, no C. HPACK (RFC 7541) and the HTTP/2
frame headers came with it and are now in VegaHTTP2Core; the WebSocket frames
(RFC 6455) and the permessage-deflate negotiation (RFC 7692) are in
VegaWebSocketCore.

It came to Vega from Garuda's `GarudaWire` module, which had vendored it from
aviancore's `AvianHTTP` (github.com/grepjava/aviancore, commit d7a4ef3, 0.7.3),
together with `Bytes.swift` and `ByteBuffer.swift` from `AvianCore`. Same
author, same licence. The rest of `GarudaWire` -- the HTTP/1.1 parser and
writer, and the header policies a server applies -- stays in Garuda, which
builds it on this module.

Changes on the way in:

- The byte helpers in `Bytes.swift` (`asciiLower`, `findByte`, the `cCR`
  constants and the rest) are `package` rather than `public`: Vega's modules
  parse with them, and they stay out of Vega's public API.
- `Bytes.swift` imports the C library rather than re-exporting it.
- VegaHTTP2's own HPACK was merged into this one; VegaWebSocket parses frame
  headers and validates UTF-8 with this module's code.
