# Releases

## 1.1.0 — 2026-10-21

Idle connections hold no read buffer. All of it is additions; nothing that
built against 1.0 changes.

- **`receive()`** on TCP, Unix and vsock streams waits holding no buffer
  and returns `ReceivedBytes`, the bytes in storage the runtime lends until
  it is dropped. Empty means end of stream. `AsyncReader` gains it too, with
  a default that reads into a receive block taken when the read needs it.
  - Under io_uring the kernel picks the buffer from the worker's
    provided-buffer ring (`PBUF_RING`, 256 buffers of 16 KiB by default,
    `VEGA_RECV_BUFS`) as the bytes arrive: one buffer-select `RECV` per
    call. `VEGA_RECV=multishot` arms one `RECV_MULTISHOT` per connection
    instead. It is not the default: the receive stays on the ring of the
    worker that armed it, so its bytes wait for that worker to poll.
    `VEGA_RECV=readiness` waits for readiness and reads.
  - A busy worker polls its ring between jobs once the kernel has flagged
    completions (`IORING_SQ_TASKRUN`) and a millisecond has passed since it
    last did, not only every 61 jobs: a slow request's p99 behind a busy
    worker went from 21 ms to 19 ms, and from 21 to 18 under multishot.
  - epoll, kqueue, IOCP and AFD wait for readiness (IOCP with its zero-byte
    `WSARecv`) and read into a 16 KiB receive block, from a short
    per-worker list.
- **`tryRead(into:)`** reads what has arrived without waiting, and returns
  nil when nothing has: Tokio's `try_read`.
- **`IOBuffer.releaseStorage()`** gives a buffer's storage back while its
  owner waits; a 16 KiB buffer's goes to the receive-block list, and the
  next write or read takes storage again.
- **TLS holds nothing while idle.** `TLSStream` and its read half have
  their own `receive()`: when the engine has no plaintext to give it waits
  on the transport's `receive()` and takes a receive block only once
  ciphertext has come. Ciphertext is decrypted in place, the inbound buffer
  gives its storage back when empty, OpenSSL runs with
  `SSL_MODE_RELEASE_BUFFERS`, and the engine's output buffer is freed
  before a wait. Receive offload (kTLS) keeps its bounded read.

Garuda 2.2 waits in `receive()` once a connection has been quiet for 100 ms:
27.0 KiB per idle connection becomes 21.5 KiB, and 41.2 becomes 24.5 over
TLS, the same under every receive mode.

---

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
