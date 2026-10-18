// VegaCrypto's platforms and traits only: QUIC's TLS 1.3 is built on it.
#if (os(Linux) || os(macOS) || os(Windows)) && (OpenSSL || BoringSSL)
import Vega
import VegaIO
@_exported import VegaHTTP
@_spi(Garuda) @_exported import VegaHTTP3Core
@_spi(Garuda) import VegaQUICCore
@_exported import VegaQUIC

/// Why an HTTP/3 request failed.
///
/// A struct rather than an enum, so that kinds of failure can be added
/// without breaking anyone's exhaustive `switch`: switch over `code`, or
/// compare the error itself where its kind carries nothing more
/// (`catch HTTP3ClientError.malformedResponse`, `error == .malformedResponse`).
public struct HTTP3ClientError: Error, Hashable, Sendable, CustomStringConvertible {
    /// What kind of failure this is.
    public let code: Code
    public let connectionError: QUICConnectionError?
    public let ioError: IOError?

    /// The kinds of `HTTP3ClientError`.
    public struct Code: Hashable, Sendable, CustomStringConvertible {
        let rawValue: UInt8

        /// The QUIC connection failed or closed: `connectionError` says how.
        public static let connection = Code(rawValue: 0)
        /// The request stream was reset, by the server or for a broken
        /// response.
        public static let stream = Code(rawValue: 1)
        /// The response broke HTTP/3's rules (RFC 9114 section 4.1.2).
        public static let malformedResponse = Code(rawValue: 2)
        /// The response body was longer than the configuration allows.
        public static let bodyTooLarge = Code(rawValue: 3)

        public var description: String {
            let names = ["connection", "stream", "malformedResponse", "bodyTooLarge"]
            return Int(rawValue) < names.count ? names[Int(rawValue)] : "code \(rawValue)"
        }
    }

    init(_ code: Code, connectionError: QUICConnectionError? = nil, ioError: IOError? = nil) {
        self.code = code
        self.connectionError = connectionError
        self.ioError = ioError
    }

    /// The QUIC connection failed or closed: `connectionError` says how.
    public static func connection(_ connectionError: QUICConnectionError) -> HTTP3ClientError { HTTP3ClientError(.connection, connectionError: connectionError) }
    /// The request stream was reset, by the server or for a broken
    /// response.
    public static func stream(_ ioError: IOError) -> HTTP3ClientError { HTTP3ClientError(.stream, ioError: ioError) }
    /// The response broke HTTP/3's rules (RFC 9114 section 4.1.2).
    public static let malformedResponse = HTTP3ClientError(.malformedResponse)
    /// The response body was longer than the configuration allows.
    public static let bodyTooLarge = HTTP3ClientError(.bodyTooLarge)

    public var description: String {
        switch code {
        case .connection: "\(connectionError!)"
        case .stream: "request stream failed: \(ioError!)"
        case .malformedResponse: "malformed HTTP/3 response"
        case .bodyTooLarge: "HTTP/3 response body too large"
        default: "\(code)"
        }
    }
}

/// An HTTP/3 client connection, for use inside
/// `HTTP3Client.withConnection`. Requests may be sent from many tasks at
/// once; each gets a stream of its own.
public final class HTTP3Client: Sendable {
    let connection: QUICConnection
    let configuration: HTTP3Configuration
    let authority: String

    init(_ connection: QUICConnection, configuration: HTTP3Configuration, authority: String) {
        self.connection = connection
        self.configuration = configuration
        self.authority = authority
    }

    /// Connect to `host`:`port` over `endpoint` (a client `QUICEndpoint.bind`),
    /// run `body` with a client, then close the connection.
    ///
    /// ```swift
    /// let endpoint = try QUICEndpoint.bind(runtime: rt)
    /// let response = try await HTTP3Client.withConnection(endpoint, host: "example.com") { client in
    ///     try await client.send(HTTPRequest(target: "/"))
    /// }
    /// ```
    public static func withConnection<T>(
        _ endpoint: QUICEndpoint, host: String, port: Int = 443,
        certificateVerification: QUICCertificateVerification = .system,
        configuration: HTTP3Configuration = .init(),
        _ body: (HTTP3Client) async throws -> T
    ) async throws -> T {
        var quic = QUICClientConfiguration(serverName: host, applicationProtocols: [HTTP3Server.applicationProtocol],
                                    certificateVerification: certificateVerification)
        quic.initialMaxStreamsUni = 8
        let connection: QUICConnection
        do throws(QUICConnectionError) {
            connection = try await endpoint.connect(host: host, port: port, configuration: quic)
        } catch {
            throw HTTP3ClientError.connection(error)
        }
        defer { connection.close(code: HTTP3Error.noError) }
        let authority = port == 443 ? host : "\(host):\(port)"
        let client = HTTP3Client(connection, configuration: configuration, authority: authority)
        // Our control stream with SETTINGS, kept open as long as the
        // connection; and the server's streams, read so they never stall.
        let control = try? await connection.openStream(unidirectional: true)
        let settings = h3Settings([(HTTP3Setting.maxFieldSectionSize, UInt64(configuration.maxFieldSectionSize)),
                                   (HTTP3Setting.qpackMaxTableCapacity, 0),
                                   (HTTP3Setting.qpackBlockedStreams, 0)])
        try? await control?.write(h3Varint(HTTP3StreamType.control) + h3Frame(HTTP3FrameType.settings, settings))
        let reader = Runtime.spawn {
            await withTaskGroup(of: Void.self) { group in
                while let stream = await connection.acceptStream() {
                    group.addTask { await drain(stream) }
                }
            }
        }
        defer { reader.cancel() }
        let result = try await body(client)
        _ = control
        return result
    }

    /// A server stream: its control stream and QPACK streams carry nothing
    /// a client with no dynamic table needs; push streams aren't allowed
    /// (no MAX_PUSH_ID was sent).
    static func drain(_ stream: QUICStream) async {
        var buffer = IOBuffer(capacity: 4096)
        while true {
            buffer.clear()
            guard let n = try? await stream.read(into: &buffer), n > 0 else { return }
        }
    }

    /// Send `request` and wait for its response. The request's Host field,
    /// or the connection's host, becomes `:authority`.
    public func send(_ request: HTTPRequest) async throws(HTTP3ClientError) -> HTTPResponse {
        let stream: QUICStream
        do throws(QUICConnectionError) {
            stream = try await connection.openStream()
        } catch {
            throw .connection(error)
        }
        var fields = request.head.fields
        let host = fields["host"] ?? authority
        fields.remove("host")
        let isConnect = request.head.method == .connect
        var pseudo: [(String, String)] = [(":method", request.head.method.rawValue)]
        if isConnect {
            pseudo.append((":authority", request.head.target))
        } else {
            pseudo += [(":scheme", "https"), (":authority", host), (":path", request.head.target)]
        }
        var out = h3HeadersFrame(pseudo: pseudo, fields)
        if !request.body.isEmpty { out += h3Frame(HTTP3FrameType.data, request.body) }
        do throws(IOError) {
            try await stream.write(out)
            if !isConnect { stream.finish() }
        } catch {
            // A server may answer before the request is whole and ask us to
            // stop sending (RFC 9114 section 4.1.1): the answer still comes.
            guard stream.error?.code == .stopSending else { throw .stream(error) }
        }
        return try await readResponse(stream, head: request.head.method == .head)
    }

    private func readResponse(_ stream: QUICStream, head: Bool) async throws(HTTP3ClientError) -> HTTPResponse {
        var frames = FramedRead(reading: stream,
                                decoder: HTTP3FrameDecoder(maxPayload: max(configuration.maxFieldSectionSize, 64 * 1024),
                                                           maxData: configuration.maxBodySize))
        var response: HTTPResponseHead?
        var body: [UInt8] = []
        while true {
            let frame: HTTP3RawFrame?
            do throws(FramedError) { frame = try await frames.next() } catch {
                if let e = error.ioError { throw .stream(e) }
                if error.codecError?.code == .frameTooLong {
                    stream.stopSending(code: HTTP3Error.requestCancelled)
                    throw .bodyTooLarge
                }
                throw .malformedResponse
            }
            guard let frame else { break }
            switch frame.type {
            case HTTP3FrameType.headers:
                guard let fields = h3DecodeFields(frame.payload, maxSize: configuration.maxFieldSectionSize) else {
                    throw .malformedResponse
                }
                if response == nil {
                    guard let h = fields.responseHead(version: .http3) else { throw .malformedResponse }
                    // Informational answers come before the real one.
                    if h.status >= 100 && h.status < 200 { continue }
                    response = h
                } else {
                    guard let trailers = fields.trailers() else { throw .malformedResponse }
                    for (name, value) in trailers { response!.fields.append(name: name, value: value) }
                }
            case HTTP3FrameType.data:
                guard response != nil else { throw .malformedResponse }
                if body.count + frame.payload.count > configuration.maxBodySize {
                    stream.stopSending(code: HTTP3Error.requestCancelled)
                    throw .bodyTooLarge
                }
                body += frame.payload
            case HTTP3FrameType.settings, HTTP3FrameType.goaway, HTTP3FrameType.maxPushID,
                 HTTP3FrameType.cancelPush, HTTP3FrameType.pushPromise:
                throw .malformedResponse
            default:
                if HTTP3FrameType.isReservedFromHTTP2(frame.type) { throw .malformedResponse }
            }
        }
        guard let response else { throw .malformedResponse }
        if !head, let length = response.fields["content-length"], Int(length) != body.count,
           response.status != 204, response.status != 304 {
            throw .malformedResponse
        }
        return HTTPResponse(head: response, body: body)
    }
}
#endif
