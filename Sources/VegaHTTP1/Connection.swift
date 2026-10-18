import Vega
import VegaIO

/// HTTP/1.1 serving with whole bodies: each request is read in full, the
/// handler answers it, and the response goes out with a Content-Length.
///
/// ```swift
/// let listener = try TCPListener.bind(host: "0.0.0.0", port: 8080)
/// while true {
///     let conn = try await listener.accept()
///     runtime.spawn(with: conn) { conn in
///         try? await HTTP1Server.serve(conn) { request in
///             HTTPResponse(body: "hello")
///         }
///     }
/// }
/// ```
///
/// For streamed bodies or upgrades, use `HTTP1RequestDecoder` and
/// `HTTP1ResponseEncoder` directly.
public enum HTTP1Server {
    /// Serve requests on `stream` until the client closes it, a request asks
    /// to close, or one is malformed (answered with its 4xx and a close). A
    /// handler that throws is answered with 500.
    ///
    /// Once `shutdown` triggers, an idle connection (waiting for a request's
    /// head) returns at once, and a request in progress is answered with
    /// `connection: close` before returning. Waiting for a head, the task is
    /// cancelled by the trigger; the caller then closes the connection.
    public static func serve<Stream: AsyncReader & AsyncWriter & ~Copyable>(
        _ stream: borrowing Stream,
        configuration: HTTP1Configuration = .init(),
        shutdown: ShutdownToken? = nil,
        _ handler: (HTTPRequest) async throws -> HTTPResponse
    ) async throws(IOError) {
        var reading = Reading(HTTP1RequestDecoder(limits: configuration.limits), capacity: configuration.bufferSize)
        var encoder = HTTP1ResponseEncoder()
        var output = IOBuffer(capacity: configuration.bufferSize)
        var head: HTTPRequestHead?
        var body: [UInt8] = []

        while true {
            let part: HTTPRequestPart?
            do throws(HTTP1Error) {
                if head == nil, let shutdown {
                    // Between requests: shutdown ends the wait for the next.
                    if shutdown.isTriggered && !reading.hasBuffered { return }
                    part = try await shutdown.cancelOnTrigger { () async throws(HTTP1Error) in
                        try await reading.next(from: stream)
                    }
                    if shutdown.isTriggered && Task.isCancelled { return }
                } else {
                    part = try await reading.next(from: stream)
                }
            } catch {
                switch error.code {
                case .io:
                    let e = error.ioError!
                    if shutdown?.isTriggered == true && e == .cancelled { return }
                    throw e
                case .truncated: return // the client went away mid-request
                default:
                    try await refuse(error.status, on: stream)
                    return
                }
            }
            guard let part else { return }

            switch part {
            case .head(let h):
                head = h
                body = []
                if let n = h.fields["content-length"].flatMap({ Int($0) }), n > configuration.maxBodySize {
                    try await refuse(413, on: stream)
                    return
                }
                let hasBody = h.fields.contains("transfer-encoding") || h.fields["content-length"].map { $0 != "0" } == true
                if hasBody, h.version.minor >= 1, h.fields.containsToken("100-continue", in: "expect") {
                    try await write("HTTP/1.1 100 Continue\r\n\r\n", to: stream)
                }
            case .body(let bytes):
                guard body.count + bytes.count <= configuration.maxBodySize else {
                    try await refuse(413, on: stream)
                    return
                }
                body += bytes
            case .end:
                guard let requestHead = head else { return }
                head = nil
                var response: HTTPResponse
                do {
                    response = try await handler(HTTPRequest(head: requestHead, body: body))
                } catch {
                    response = HTTPResponse(status: 500)
                }
                body = []
                let close = prepare(&response, for: requestHead, closing: shutdown?.isTriggered == true)
                encoder.requestReceived(requestHead.method)
                output.clear()
                do throws(HTTP1Error) {
                    try encoder.encodePart(.head(response.head), into: &output)
                    if !response.body.isEmpty { try encoder.encodePart(.body(response.body), into: &output) }
                    try encoder.encodePart(.end(nil), into: &output)
                } catch {
                    try await refuse(500, on: stream)
                    return
                }
                try await stream.write(output)
                if close { return }
            }
        }
    }

    /// Frame `response` for `request`. Returns whether to close afterwards.
    private static func prepare(_ response: inout HTTPResponse, for request: HTTPRequestHead,
                                closing: Bool) -> Bool {
        let status = response.head.status
        let fields = response.head.fields
        if !(status < 200 || status == 204 || status == 304),
           !fields.contains("content-length"), !fields.contains("transfer-encoding") {
            response.head.fields["content-length"] = String(response.body.count)
        }
        if request.method == .head { response.body = [] }
        let close = closing || !request.keepAlive || !response.head.keepAlive || status == 101
        if close && status != 101 && !fields.containsToken("close", in: "connection") {
            response.head.fields.append(name: "connection", value: "close")
        }
        return close
    }

    /// Answer with `status` and no body, then close.
    private static func refuse<Stream: AsyncWriter & ~Copyable>(_ status: Int, on stream: borrowing Stream) async throws(IOError) {
        let text = "HTTP/1.1 \(status) \(HTTPResponseHead.reason(status))\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        try await write(text, to: stream)
    }

    private static func write<Stream: AsyncWriter & ~Copyable>(_ text: String, to stream: borrowing Stream) async throws(IOError) {
        var buffer = IOBuffer(capacity: text.utf8.count)
        buffer.append(text)
        try await stream.write(buffer)
    }
}

/// An HTTP/1.1 client connection over any stream, with whole bodies.
///
/// ```swift
/// let tcp = try await TCPStream.connect(host: "example.com", port: 80)
/// var http = HTTP1Client(tcp)
/// let response = try await http.send(HTTPRequest(target: "/", fields: ["host": "example.com"]))
/// ```
///
/// Requests go one at a time; after a response that ends with the
/// connection, `isReusable` turns false.
public struct HTTP1Client<Stream: AsyncReader & AsyncWriter & ~Copyable>: ~Copyable {
    public var stream: Stream
    /// A bigger response body fails with `.bodyTooLarge`.
    public var maxBodySize: Int
    private var reading: Reading<HTTP1ResponseDecoder>
    private var encoder = HTTP1RequestEncoder()
    private var output: IOBuffer
    private var failed = false

    public init(_ stream: consuming Stream, configuration: HTTP1Configuration = .init()) {
        self.stream = stream
        self.maxBodySize = configuration.maxBodySize
        reading = Reading(HTTP1ResponseDecoder(limits: configuration.limits), capacity: configuration.bufferSize)
        output = IOBuffer(capacity: configuration.bufferSize)
    }

    /// Whether another request can be sent.
    public var isReusable: Bool { !failed && reading.decoder.isReusable }

    /// Send `request` and read its response. A request with a body and no
    /// framing gets a Content-Length. HTTP/1.1 requests need a Host field.
    public mutating func send(_ request: HTTPRequest) async throws(HTTP1Error) -> HTTPResponse {
        guard isReusable else { throw .io(.brokenPipe) }
        do throws(HTTP1Error) {
            return try await exchange(request)
        } catch {
            failed = true
            throw error
        }
    }

    private mutating func exchange(_ request: HTTPRequest) async throws(HTTP1Error) -> HTTPResponse {
        var head = request.head
        if head.version.minor >= 1 && !head.fields.contains("host") { throw .missingHost }
        let bodiless: [HTTPMethod] = [.get, .head, .delete, .options, .trace, .connect]
        if !head.fields.contains("content-length") && !head.fields.contains("transfer-encoding")
            && (!request.body.isEmpty || !bodiless.contains(head.method)) {
            head.fields["content-length"] = String(request.body.count)
        }
        output.clear()
        try encoder.encodePart(.head(head), into: &output)
        if !request.body.isEmpty { try encoder.encodePart(.body(request.body), into: &output) }
        try encoder.encodePart(.end(nil), into: &output)
        reading.decoder.requestSent(head.method)
        do throws(IOError) {
            try await stream.write(output)
        } catch {
            throw .io(error)
        }

        var response: HTTPResponseHead?
        var body: [UInt8] = []
        while let part = try await reading.next(from: stream) {
            switch part {
            case .head(let h):
                // Interim responses (100 Continue, 103 Early Hints) are skipped.
                response = h.status < 200 && h.status != 101 ? nil : h
            case .body(let bytes):
                guard body.count + bytes.count <= maxBodySize else { throw .bodyTooLarge }
                body += bytes
            case .end:
                if let response { return HTTPResponse(head: response, body: body) }
            }
        }
        throw .truncated
    }

    /// The bytes read past the last response: after a 101, the start of
    /// the new protocol. Take them before `intoStream()`.
    public var leftover: [UInt8] { reading.leftover }

    /// Give back the stream.
    public consuming func intoStream() -> Stream {
        stream
    }
}

/// A decoder that `Reading` drives.
protocol PartDecoder {
    associatedtype Part
    mutating func decodePart(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Part, consumed: Int)?
    mutating func decodePartAtEnd(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Part, consumed: Int)?
}

extension HTTP1RequestDecoder: PartDecoder {}
extension HTTP1ResponseDecoder: PartDecoder {}

/// Bytes read from a stream and decoded in place, as `FramedRead` does.
struct Reading<D: PartDecoder>: ~Copyable {
    var decoder: D
    private var buffer: IOBuffer
    private var start = 0
    private var ended = false

    init(_ decoder: D, capacity: Int) {
        self.decoder = decoder
        buffer = IOBuffer(capacity: capacity)
    }

    /// Whether bytes past the last part are waiting to be decoded.
    var hasBuffered: Bool { buffer.count > start }

    var leftover: [UInt8] {
        let s = start
        return buffer.withUnsafeBytes { Array($0[s...]) }
    }

    /// The next part; nil once the stream has ended between messages.
    mutating func next<Reader: AsyncReader & ~Copyable>(from reader: borrowing Reader) async throws(HTTP1Error) -> D.Part? {
        while true {
            let s = start
            let atEnd = ended
            let decoded = try buffer.withUnsafeBytes { all throws(HTTP1Error) in
                let rest = UnsafeRawBufferPointer(rebasing: all[s...])
                return atEnd ? try decoder.decodePartAtEnd(rest) : try decoder.decodePart(rest)
            }
            if let decoded {
                start += decoded.consumed
                return decoded.item
            }
            if ended { return nil }
            if start > 0 {
                buffer.consume(start)
                start = 0
            }
            if buffer.spareCapacity == 0 { buffer.reserveCapacity(buffer.capacity * 2) }
            do throws(IOError) {
                if try await reader.read(into: &buffer) == 0 { ended = true }
            } catch {
                throw .io(error)
            }
        }
    }
}
