// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Synchronization
import Vega
import VegaIO
import VegaHTTP
@_spi(Garuda) import VegaHTTP3Core
@_spi(Garuda) import VegaQUICCore
import VegaQUIC
import VegaCrypto

/// HTTP/3's limits, for `HTTP3Server` and `HTTP3Client`.
public struct HTTP3Configuration: Sendable {
    /// The largest field section, decoded, this end accepts
    /// (SETTINGS_MAX_FIELD_SECTION_SIZE).
    public var maxHeaderSize: Int
    /// A bigger body is refused: a request with 413, a response with an
    /// error.
    public var maxBodySize: Int

    public init(maxHeaderSize: Int = 64 * 1024, maxBodySize: Int = 8 << 20) {
        self.maxHeaderSize = maxHeaderSize
        self.maxBodySize = maxBodySize
    }
}

/// HTTP/3 serving with whole bodies, over a `QUICEndpoint`: each request
/// runs its handler in a task of its own.
///
/// ```swift
/// let endpoint = try QUICEndpoint.bind(port: 443,
///     configuration: HTTP3Server.quicConfiguration(certificate: key), runtime: rt)
/// await HTTP3Server.serve(endpoint) { request in HTTPResponse(body: "hello") }
/// ```
///
/// QPACK runs with the static table only (a dynamic table capacity of 0),
/// which every peer must accept. No server push.
public enum HTTP3Server {
    /// The ALPN identifier, "h3".
    public static let applicationProtocol = "h3"

    /// A QUIC configuration for HTTP/3 with `certificate`.
    public static func quicConfiguration(certificate: CertificateKey) -> QUICServerConfiguration {
        var config = QUICServerConfiguration(certificateKey: certificate, applicationProtocols: [applicationProtocol])
        // Room for the peer's control and QPACK streams, and a few more.
        config.initialMaxStreamsUni = 8
        return config
    }

    /// Serve every connection the endpoint accepts, until it is closed.
    ///
    /// Once `shutdown` triggers, no more connections are taken, each one
    /// served drains as the one-connection `serve` does, and this returns
    /// when they all have. The endpoint stays open: close it after.
    public static func serve(_ endpoint: QUICEndpoint, configuration: HTTP3Configuration = .init(),
                             shutdown: ShutdownToken? = nil,
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        await withTaskGroup(of: Void.self) { group in
            while true {
                let (connection, late) = await accept(endpoint, until: shutdown)
                for connection in [connection, late] {
                    guard let connection else { continue }
                    group.addTask { await serve(connection, configuration: configuration, shutdown: shutdown, handler) }
                }
                if connection == nil { break }
            }
        }
    }

    /// The endpoint's next connection, or nil once it is closed or
    /// `shutdown` triggers. One that arrived as the trigger did comes back
    /// as `late`, to be served (and drained) rather than dropped.
    private static func accept(_ endpoint: QUICEndpoint,
                               until shutdown: ShutdownToken?) async -> (QUICConnection?, late: QUICConnection?) {
        guard let shutdown else { return (await endpoint.accept(), nil) }
        if shutdown.isTriggered { return (nil, nil) }
        return await withTaskGroup(of: QUICConnection?.self) { group in
            // accept returns nil when cancelled, and wait throws.
            group.addTask { await endpoint.accept() }
            group.addTask {
                try? await shutdown.wait()
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            var late: QUICConnection?
            while let other = await group.next() {
                if let other { late = other }
            }
            return first == nil || shutdown.isTriggered ? (nil, first ?? late) : (first, nil)
        }
    }

    /// Serve one connection until it closes.
    ///
    /// Once `shutdown` triggers, the server sends GOAWAY, refuses new
    /// requests (H3_REQUEST_REJECTED, which a client may retry elsewhere),
    /// and closes the connection (H3_NO_ERROR) when the requests it took
    /// are answered and their responses delivered.
    public static func serve(_ connection: QUICConnection, configuration: HTTP3Configuration = .init(),
                             shutdown: ShutdownToken? = nil,
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        guard connection.applicationProtocol == applicationProtocol else {
            connection.close(code: HTTP3ErrorCode.versionFallback.rawValue)
            return
        }
        let peer = PeerStreams()
        // Our control stream, with our SETTINGS first (RFC 9114 section 6.2.1).
        // It stays open as long as the connection does.
        guard let control = try? await connection.openStream(unidirectional: true) else { return }
        let settings = h3Settings([(HTTP3Setting.maxFieldSectionSize, UInt64(configuration.maxHeaderSize)),
                                   (HTTP3Setting.qpackMaxTableCapacity, 0),
                                   (HTTP3Setting.qpackBlockedStreams, 0)])
        try? await control.write(h3Varint(HTTP3StreamType.control) + h3Frame(HTTP3FrameType.settings, settings))

        let drain = Drain()
        await withTaskGroup(of: Void.self) { group in
            if let shutdown {
                group.addTask {
                    // Throws when the group is cancelled: the connection is over.
                    guard (try? await shutdown.wait()) != nil else { return }
                    let (next, idle) = drain.start()
                    // RFC 9114 section 5.2: the first request stream not taken.
                    try? await control.write(h3Frame(HTTP3FrameType.goaway, h3Varint(next)))
                    if !idle {
                        guard (try? await drain.idle.notified()) != nil else { return }
                    }
                    connection.closeWhenDone(code: HTTP3ErrorCode.noError.rawValue)
                }
            }
            while let stream = await connection.acceptStream() {
                if stream.isUnidirectional {
                    group.addTask { await readUnidirectional(stream, connection, peer) }
                } else if drain.admit(stream.id) {
                    group.addTask {
                        await serveRequest(stream, connection, configuration, handler)
                        drain.done()
                    }
                } else {
                    stream.stopSending(code: HTTP3ErrorCode.requestRejected.rawValue)
                    stream.reset(code: HTTP3ErrorCode.requestRejected.rawValue)
                }
            }
            group.cancelAll()
        }
        _ = control
    }

    /// A connection's requests in progress, and whether it is draining.
    final class Drain: Sendable {
        struct State {
            var active = 0
            var draining = false
            /// One past the last request stream taken (client bidirectional
            /// IDs go up by 4).
            var next: UInt64 = 0
        }
        let state = Locked(State())
        /// Notified when a drain finds, or leaves, nothing in progress.
        let idle = Notify()

        /// Take a request on stream `id`, unless draining.
        func admit(_ id: UInt64) -> Bool {
            state.withLock { s in
                if s.draining { return false }
                s.active += 1
                s.next = max(s.next, id + 4)
                return true
            }
        }

        func done() {
            let last = state.withLock { s in
                s.active -= 1
                return s.draining && s.active == 0
            }
            if last { idle.notifyOne() }
        }

        /// Start draining: the GOAWAY's stream ID, and whether nothing is
        /// in progress.
        func start() -> (next: UInt64, idle: Bool) {
            state.withLock { s in
                s.draining = true
                return (s.next, s.active == 0)
            }
        }
    }

    /// Which of the peer's critical streams have been seen: each once.
    final class PeerStreams: Sendable {
        let seen = Locked<Set<UInt64>>([])
        func first(_ type: UInt64) -> Bool { seen.withLock { $0.insert(type).inserted } }
    }

    /// The peer's control stream, QPACK streams, or one of a type we don't
    /// know (ignored, as RFC 9114 section 6.2.3 says).
    static func readUnidirectional(_ stream: QUICStream, _ connection: QUICConnection,
                                   _ peer: PeerStreams) async {
        var reader = UnidirectionalReader(stream)
        guard let type = await reader.varint() else { return }
        switch type {
        case HTTP3StreamType.control:
            guard peer.first(type) else { return connection.close(code: HTTP3ErrorCode.streamCreationError.rawValue) }
            var frames = FramedRead(reading: stream, decoder: HTTP3FrameDecoder(maxPayload: 64 * 1024))
            frames.prepend(reader.rest)
            var first = true
            while true {
                let frame: HTTP3RawFrame?
                do throws(FramedError) { frame = try await frames.next() } catch {
                    return connection.close(code: HTTP3ErrorCode.frameError.rawValue)
                }
                guard let frame else {
                    // RFC 9114 section 6.2.1: closing it is a connection error.
                    return connection.close(code: HTTP3ErrorCode.closedCriticalStream.rawValue)
                }
                if first {
                    first = false
                    guard frame.type == HTTP3FrameType.settings else {
                        return connection.close(code: HTTP3ErrorCode.missingSettings.rawValue)
                    }
                    guard h3ParseSettings(frame.payload) != nil else {
                        return connection.close(code: HTTP3ErrorCode.settingsError.rawValue)
                    }
                    continue
                }
                switch frame.type {
                case HTTP3FrameType.settings, HTTP3FrameType.data, HTTP3FrameType.headers, HTTP3FrameType.pushPromise:
                    return connection.close(code: HTTP3ErrorCode.frameUnexpected.rawValue)
                default:
                    // GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, unknown: nothing to do
                    // for a server that neither pushes nor drains early.
                    if HTTP3FrameType.isReservedFromHTTP2(frame.type) {
                        return connection.close(code: HTTP3ErrorCode.frameUnexpected.rawValue)
                    }
                }
            }
        case HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
            guard peer.first(type) else { return connection.close(code: HTTP3ErrorCode.streamCreationError.rawValue) }
            // With no dynamic table, nothing on these matters; they must stay
            // open, and are read so their flow control never stalls.
            var buffer = IOBuffer(capacity: 4096)
            while true {
                buffer.clear()
                guard let n = try? await stream.read(into: &buffer) else { return }
                if n == 0 { return connection.close(code: HTTP3ErrorCode.closedCriticalStream.rawValue) }
            }
        case HTTP3StreamType.push:
            // Only servers push.
            connection.close(code: HTTP3ErrorCode.streamCreationError.rawValue)
        default:
            stream.stopSending(code: HTTP3ErrorCode.streamCreationError.rawValue)
        }
    }

    /// One request stream: HEADERS, DATA, perhaps trailing HEADERS; then
    /// the handler, and its answer.
    static func serveRequest(_ stream: QUICStream, _ connection: QUICConnection,
                             _ configuration: HTTP3Configuration,
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        var frames = FramedRead(reading: stream,
                                decoder: HTTP3FrameDecoder(maxPayload: max(configuration.maxHeaderSize, 64 * 1024),
                                                           maxData: configuration.maxBodySize))
        var head: HTTPRequestHead?
        var body: [UInt8] = []
        var tooLarge = false
        while true {
            let frame: HTTP3RawFrame?
            do throws(FramedError) { frame = try await frames.next() } catch {
                // One DATA frame longer than the body may be: 413, below.
                if error.codecError?.code == .frameTooLong, head != nil {
                    tooLarge = true
                    break
                }
                if stream.error == nil { stream.reset(code: HTTP3ErrorCode.frameError.rawValue) }
                return
            }
            guard let frame else { break }
            switch frame.type {
            case HTTP3FrameType.headers:
                guard let fields = h3DecodeFields(frame.payload, maxSize: configuration.maxHeaderSize) else {
                    return connection.close(code: HTTP3ErrorCode.qpackDecompressionFailed.rawValue)
                }
                if head == nil {
                    guard let h = fields.requestHead(version: .http3) else {
                        return messageError(stream)
                    }
                    head = h
                } else {
                    // Trailers join the fields: whole messages have nowhere
                    // else to put them.
                    guard let trailers = fields.trailers() else { return messageError(stream) }
                    for (name, value) in trailers { head!.fields.append(name: name, value: value) }
                }
            case HTTP3FrameType.data:
                guard head != nil else { return connection.close(code: HTTP3ErrorCode.frameUnexpected.rawValue) }
                if body.count + frame.payload.count > configuration.maxBodySize {
                    tooLarge = true
                } else if !tooLarge {
                    body += frame.payload
                }
            case HTTP3FrameType.settings, HTTP3FrameType.goaway, HTTP3FrameType.maxPushID,
                 HTTP3FrameType.cancelPush, HTTP3FrameType.pushPromise:
                return connection.close(code: HTTP3ErrorCode.frameUnexpected.rawValue)
            default:
                if HTTP3FrameType.isReservedFromHTTP2(frame.type) {
                    return connection.close(code: HTTP3ErrorCode.frameUnexpected.rawValue)
                }
            }
            if tooLarge { break }
        }
        guard let head else { return messageError(stream) }
        if tooLarge {
            // Answered before the request is whole: the client is told to
            // stop sending, which isn't an error (RFC 9114 section 4.1.1).
            stream.stopSending(code: HTTP3ErrorCode.noError.rawValue)
            await respond(stream, HTTPResponse(status: 413), head: false)
            return
        }
        if let length = head.fields["content-length"], Int(length) != body.count { return messageError(stream) }
        let response: HTTPResponse
        do {
            response = try await handler(HTTPRequest(head: head, body: body))
        } catch {
            response = HTTPResponse(status: 500)
        }
        await respond(stream, response, head: head.method == .head)
    }

    /// RFC 9114 section 4.1.2: a malformed request is a stream error.
    static func messageError(_ stream: QUICStream) {
        stream.reset(code: HTTP3ErrorCode.messageError.rawValue)
        stream.stopSending(code: HTTP3ErrorCode.messageError.rawValue)
    }

    static func respond(_ stream: QUICStream, _ response: HTTPResponse, head: Bool) async {
        var fields = response.head.fields
        if !head && fields["content-length"] == nil && response.status != 204 && response.status != 304 {
            fields.append(name: "content-length", value: String(response.body.count))
        }
        var out = h3HeadersFrame(status: response.status, fields)
        if !head && !response.body.isEmpty { out += h3Frame(HTTP3FrameType.data, response.body) }
        try? await stream.write(out)
        stream.finish()
    }
}

/// Reads a unidirectional stream's type, then hands what it read past it
/// to a `FramedRead`.
struct UnidirectionalReader: ~Copyable {
    let stream: QUICStream
    var buffer = IOBuffer(capacity: 64)
    var consumed = 0

    init(_ stream: QUICStream) { self.stream = stream }

    mutating func varint() async -> UInt64? {
        while true {
            let parsed = buffer.withUnsafeBytes { b -> (UInt64, Int)? in
                guard let base = b.baseAddress else { return nil }
                var r = QUICReader(base.assumingMemoryBound(to: UInt8.self) + consumed, b.count - consumed)
                guard let v = r.varint() else { return nil }
                return (v, r.offset)
            }
            if let parsed {
                consumed += parsed.1
                return parsed.0
            }
            guard buffer.spareCapacity > 0, let n = try? await stream.read(into: &buffer), n > 0 else { return nil }
        }
    }

    /// The bytes read past the type, which belong to what follows.
    var rest: [UInt8] { buffer.withUnsafeBytes { Array($0[consumed...]) } }
}
#endif
