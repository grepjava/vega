# Releases

## 1.0.0 — 2026-10-19

Vega's API is frozen: from 1.0, Vega follows semantic versioning. A minor
release adds; only a major one breaks. 1.0 is 0.5 reshaped so that it can
stay that way. Most of the work is renames, and a few behaviours change.

### Conventions

- **Errors are structs with a `code`**, not enums, so kinds can be added
  without breaking anyone. Match with `catch IOError.cancelled` or
  `error == .timedOut`, or switch over `error.code` with a `default`. A
  payload is a property (`error.ioError`), not a pattern binding. Enums that
  will grow are structs too (`IOBackend`, `ContentCoding`, `HashAlgorithm`).
- **Cancellation.** A wait with its own error type throws that type's
  `.cancelled`. A wait without one throws `CancellationError`: `Notify.notified()`,
  `ShutdownToken.wait()`, `TCPServer.wait()`, `SignalStream.recv()`,
  `JoinSet.next()`, `Runtime.sleep`, `Interval.tick`. A sequence of values ends
  with nil: iterators, `QUICEndpoint.accept()`, `QUICConnection.acceptStream()`.
- **Timeouts read like `Clock`:** `for:` takes a `Duration`, `until:` an instant.
- **Modules.** A protocol's networked module has its plain name and its
  sans-I/O logic is in its `Core` module. What Garuda builds on is
  `@_spi(Garuda)`; what the modules share is `package`.

### Renamed

| 0.5 | 1.0 |
|---|---|
| `Runtime.timeout(_:)` | `Runtime.timeout(for:)`, `timeout(until:)` |
| `Runtime.withIODeadline` | `Runtime.withIOTimeout(for:)`, `withIOTimeout(until:)` |
| `IODeadlineTrigger` | `IOTimeoutTrigger` |
| `withWriteStallTimeout(_:)` | `withWriteStallTimeout(for:)` |
| `Channel` | `MPSCChannel` |
| `JobStamp`, `Runtime.currentJobStamp` | `PollStamp`, `Runtime.currentPollStamp` (nil off a worker) |
| `ShutdownSignal` | `ShutdownToken` |
| `ShardOptions` | `ShardConfiguration` |
| `Runtime(workers:...)` | also `Runtime(configuration:)` with `Runtime.Configuration` |
| `Runtime.seeded`, the paused clock | `VegaTest` |
| `Decoder`, `Encoder` (VegaIO) | `FrameDecoder`, `FrameEncoder` |
| `IOBuffer.write` | `IOBuffer.append` (grows); `appendWithinCapacity` stops at the capacity |
| `halves()`, `SplitStream`, `DuplexStream.Split` | `split()` returning `StreamHalves` |
| `UDPSocket.connect(to:)` on a socket | `setPeer(_:)`; `UnixDatagram.connect(path:)` is `setPeer(path:)` |
| `Runtime.blocking` refusing when the queue is full | `Runtime.tryBlocking` (nil when full); `blocking` always waits its turn |
| `H2FrameHeader`, `H2FrameType`, `H2Flags`, `H2Error`, `H2Setting` | `HTTP2FrameHeader`, `HTTP2FrameType`, `HTTP2Flags`, `HTTP2ErrorCode`, `HTTP2Setting` |
| `WS*` (`WSCloseCode`, `WSOpcode`, `WSFrameHeader`, `WSDeflate`...) | `WebSocket*` |
| `HTTP3Error` (UInt64 constants) | `HTTP3ErrorCode` (a struct; `.rawValue`) |
| `QUICError` | `QUICErrorCode` |
| `QUICConnectionHandle`, `QUICStreamHandle` | `QUICConnection`, `QUICStream` |
| `QUICConnection`, `QUICStream` (state machines) | `QUICConnectionState`, `QUICStreamState` (VegaQUICCore) |
| `QUICServerConfig`, `QUICClientConfig` | `QUICServerConfiguration`, `QUICClientConfiguration`; `applicationProtocols: [String]`, `maxIdleTimeout: Duration`, `certificateKey(s)` |
| `HTTP1Connection` | `HTTP1Client` |
| `HTTP1Server.Configuration`, `HTTP1Limits`' `maxHeadSize`, `maxFields` | `HTTP1Configuration`; `maxHeaderSize`, `maxHeaderCount` |
| `HTTP2Configuration.maxHeaderListSize`, `HTTP3Configuration.maxFieldSectionSize` | `maxHeaderSize` |
| `TLSConfiguration.TrustRoots`, `CertificateVerifier.TrustRoots` | `TrustRoots` (VegaCrypto) |
| `TLSConfiguration.Version`, NetworkTLS's `tls_protocol_version_t` | `TLSVersion` |
| `TLSConfiguration.Verification.none` | `.disabled` |
| `CertificateVerifier.verify(chain:hostname:)` | `verify(chain:serverName:)` |
| `TCPStream.networkTLS()` | `tlsSession()` |
| `NetworkTLS.Trust.anyCertificate` | `.insecureAnyCertificate` |
| VegaTLS's `Digest`, `DigestError` | VegaCrypto's `Digest`, throwing `CryptoError` |
| `VegaExtras` | `Quiesce` in `Vega`, `VegaProxy`, `VegaCompression` |

### Changed

- `IOError` adds `limitExceeded`, `unexpectedEndOfStream`, `hostNotFound` and
  `lookupFailed`. A stream read into a full buffer throws `.limitExceeded`
  instead of returning 0, which read as end of stream.
- `IOBuffer.count` is read-only; `removeLast(_:)` trims.
- `QUICConnectionError` adds `idleTimeout`, `handshakeFailed(code:)` and
  `cancelled`. `connect` and `openStream` are cancellable. A server that never
  answers now times out: the idle timeout's floor no longer grows with each
  probe.
- `HTTP3Server.serve` takes `shutdown:` and drains with GOAWAY, as the HTTP/1
  and HTTP/2 servers do. Bodies default to at most 8 MiB in all three.
- VegaWire's `ByteBuffer` and `ByteSpan` are public.
- A TLS client that verifies needs a server name. `Decompressor` needs an
  explicit limit.

VegaNIO and the swift-metrics and swift-log adapters are in a repository of
their own, [vega-nio](https://github.com/grepjava/vega-nio), which builds against this release.
