// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Synchronization
import Vega
import VegaIO
import VegaHTTP1
import VegaHTTP3Core
import VegaQUICCore
import VegaQUIC
import VegaCrypto

/// HTTP/3's limits.
public struct HTTP3Configuration: Sendable {
    /// The largest request or response body taken whole; a larger request
    /// is answered 413.
    public var maxBodySize: Int
    /// The largest field section (RFC 9114 SETTINGS_MAX_FIELD_SECTION_SIZE).
    public var maxFieldSectionSize: Int

    public init(maxBodySize: Int = 16 << 20, maxFieldSectionSize: Int = 64 * 1024) {
        self.maxBodySize = maxBodySize
        self.maxFieldSectionSize = maxFieldSectionSize
    }
}

/// HTTP/3 serving with whole bodies, over a `QUICEndpoint`: each request
/// runs its handler in a task of its own.
///
/// ```swift
/// let endpoint = try QUICEndpoint.listen(port: 443,
///     configuration: HTTP3Server.quicConfiguration(certificate: key), runtime: rt)
/// await HTTP3Server.serve(endpoint) { request in HTTPResponse(body: "hello") }
/// ```
///
/// QPACK runs with the static table only (a dynamic table capacity of 0),
/// which every peer must accept. No server push.
public enum HTTP3Server {
    /// The ALPN identifier, "h3".
    public static let alpn: [UInt8] = Array("h3".utf8)

    /// A QUIC configuration for HTTP/3 with `certificate`.
    public static func quicConfiguration(certificate: CertificateKey) -> QUICServerConfig {
        var config = QUICServerConfig(certKey: certificate, alpn: [alpn])
        // Room for the peer's control and QPACK streams, and a few more.
        config.initialMaxStreamsUni = 8
        return config
    }

    /// Serve every connection the endpoint accepts, until it is closed.
    public static func serve(_ endpoint: QUICEndpoint, configuration: HTTP3Configuration = .init(),
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        await withTaskGroup(of: Void.self) { group in
            while let connection = await endpoint.accept() {
                group.addTask { await serve(connection, configuration: configuration, handler) }
            }
        }
    }

    /// Serve one connection until it closes.
    public static func serve(_ connection: QUICConnectionHandle, configuration: HTTP3Configuration = .init(),
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        guard connection.alpn == alpn else {
            connection.close(code: HTTP3Error.versionFallback)
            return
        }
        let peer = PeerStreams()
        // Our control stream, with our SETTINGS first (RFC 9114 section 6.2.1).
        // It stays open as long as the connection does.
        guard let control = try? await connection.openStream(unidirectional: true) else { return }
        let settings = h3Settings([(HTTP3Setting.maxFieldSectionSize, UInt64(configuration.maxFieldSectionSize)),
                                   (HTTP3Setting.qpackMaxTableCapacity, 0),
                                   (HTTP3Setting.qpackBlockedStreams, 0)])
        try? await control.write(h3Varint(HTTP3StreamType.control) + h3Frame(HTTP3FrameType.settings, settings))

        await withTaskGroup(of: Void.self) { group in
            while let stream = await connection.acceptStream() {
                if stream.isUnidirectional {
                    group.addTask { await readUnidirectional(stream, connection, peer) }
                } else {
                    group.addTask { await serveRequest(stream, connection, configuration, handler) }
                }
            }
            group.cancelAll()
        }
        _ = control
    }

    /// Which of the peer's critical streams have been seen: each once.
    final class PeerStreams: Sendable {
        let seen = Locked<Set<UInt64>>([])
        func first(_ type: UInt64) -> Bool { seen.withLock { $0.insert(type).inserted } }
    }

    /// The peer's control stream, QPACK streams, or one of a type we don't
    /// know (ignored, as RFC 9114 section 6.2.3 says).
    static func readUnidirectional(_ stream: QUICStreamHandle, _ connection: QUICConnectionHandle,
                                   _ peer: PeerStreams) async {
        var reader = UnidirectionalReader(stream)
        guard let type = await reader.varint() else { return }
        switch type {
        case HTTP3StreamType.control:
            guard peer.first(type) else { return connection.close(code: HTTP3Error.streamCreationError) }
            var frames = FramedRead(reading: stream, decoder: HTTP3FrameDecoder(maxPayload: 64 * 1024))
            frames.prepend(reader.rest)
            var first = true
            while true {
                let frame: HTTP3RawFrame?
                do throws(FramedError) { frame = try await frames.next() } catch {
                    return connection.close(code: HTTP3Error.frameError)
                }
                guard let frame else {
                    // RFC 9114 section 6.2.1: closing it is a connection error.
                    return connection.close(code: HTTP3Error.closedCriticalStream)
                }
                if first {
                    first = false
                    guard frame.type == HTTP3FrameType.settings else {
                        return connection.close(code: HTTP3Error.missingSettings)
                    }
                    guard h3ParseSettings(frame.payload) != nil else {
                        return connection.close(code: HTTP3Error.settingsError)
                    }
                    continue
                }
                switch frame.type {
                case HTTP3FrameType.settings, HTTP3FrameType.data, HTTP3FrameType.headers, HTTP3FrameType.pushPromise:
                    return connection.close(code: HTTP3Error.frameUnexpected)
                default:
                    // GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, unknown: nothing to do
                    // for a server that neither pushes nor drains early.
                    if HTTP3FrameType.isReservedFromHTTP2(frame.type) {
                        return connection.close(code: HTTP3Error.frameUnexpected)
                    }
                }
            }
        case HTTP3StreamType.qpackEncoder, HTTP3StreamType.qpackDecoder:
            guard peer.first(type) else { return connection.close(code: HTTP3Error.streamCreationError) }
            // With no dynamic table, nothing on these matters; they must stay
            // open, and are read so their flow control never stalls.
            var buffer = IOBuffer(capacity: 4096)
            while true {
                buffer.clear()
                guard let n = try? await stream.read(into: &buffer) else { return }
                if n == 0 { return connection.close(code: HTTP3Error.closedCriticalStream) }
            }
        case HTTP3StreamType.push:
            // Only servers push.
            connection.close(code: HTTP3Error.streamCreationError)
        default:
            stream.stopSending(code: HTTP3Error.streamCreationError)
        }
    }

    /// One request stream: HEADERS, DATA, perhaps trailing HEADERS; then
    /// the handler, and its answer.
    static func serveRequest(_ stream: QUICStreamHandle, _ connection: QUICConnectionHandle,
                             _ configuration: HTTP3Configuration,
                             _ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) async {
        var frames = FramedRead(reading: stream,
                                decoder: HTTP3FrameDecoder(maxPayload: max(configuration.maxFieldSectionSize, 64 * 1024),
                                                           maxData: configuration.maxBodySize))
        var head: HTTPRequestHead?
        var body: [UInt8] = []
        var tooLarge = false
        while true {
            let frame: HTTP3RawFrame?
            do throws(FramedError) { frame = try await frames.next() } catch {
                // One DATA frame longer than the body may be: 413, below.
                if case .codec(.frameTooLong) = error, head != nil {
                    tooLarge = true
                    break
                }
                if stream.error == nil { stream.reset(code: HTTP3Error.frameError) }
                return
            }
            guard let frame else { break }
            switch frame.type {
            case HTTP3FrameType.headers:
                guard let fields = h3DecodeFields(frame.payload, maxSize: configuration.maxFieldSectionSize) else {
                    return connection.close(code: HTTP3Error.qpackDecompressionFailed)
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
                guard head != nil else { return connection.close(code: HTTP3Error.frameUnexpected) }
                if body.count + frame.payload.count > configuration.maxBodySize {
                    tooLarge = true
                } else if !tooLarge {
                    body += frame.payload
                }
            case HTTP3FrameType.settings, HTTP3FrameType.goaway, HTTP3FrameType.maxPushID,
                 HTTP3FrameType.cancelPush, HTTP3FrameType.pushPromise:
                return connection.close(code: HTTP3Error.frameUnexpected)
            default:
                if HTTP3FrameType.isReservedFromHTTP2(frame.type) {
                    return connection.close(code: HTTP3Error.frameUnexpected)
                }
            }
            if tooLarge { break }
        }
        guard let head else { return messageError(stream) }
        if tooLarge {
            // Answered before the request is whole: the client is told to
            // stop sending, which isn't an error (RFC 9114 section 4.1.1).
            stream.stopSending(code: HTTP3Error.noError)
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
    static func messageError(_ stream: QUICStreamHandle) {
        stream.reset(code: HTTP3Error.messageError)
        stream.stopSending(code: HTTP3Error.messageError)
    }

    static func respond(_ stream: QUICStreamHandle, _ response: HTTPResponse, head: Bool) async {
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
    let stream: QUICStreamHandle
    var buffer = IOBuffer(capacity: 64)
    var consumed = 0

    init(_ stream: QUICStreamHandle) { self.stream = stream }

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
