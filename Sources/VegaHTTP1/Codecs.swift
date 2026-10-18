import Vega
import VegaIO
@_spi(Garuda) import VegaHTTP1Core
import VegaWire

/// Limits on what a decoder will buffer for one message.
public struct HTTP1Limits: Sendable {
    /// The request or status line and fields, in bytes.
    public var maxHeaderSize: Int
    /// The fields in the head, or in the trailers.
    public var maxHeaderCount: Int
    /// The trailer section after a chunked body, in bytes.
    public var maxTrailerSize: Int

    public init(maxHeaderSize: Int = 32 * 1024, maxHeaderCount: Int = 100, maxTrailerSize: Int = 32 * 1024) {
        self.maxHeaderSize = maxHeaderSize
        self.maxHeaderCount = maxHeaderCount
        self.maxTrailerSize = maxTrailerSize
    }
}

/// HTTP/1.1's limits and buffers, for `HTTP1Server` and `HTTP1Client`: as
/// `HTTP2Configuration` and `HTTP3Configuration` are for theirs.
public struct HTTP1Configuration: Sendable {
    /// The request or status line and fields, in bytes.
    public var maxHeaderSize: Int
    /// The fields in the head, or in the trailers.
    public var maxHeaderCount: Int
    /// The trailer section after a chunked body, in bytes.
    public var maxTrailerSize: Int
    /// A bigger body is refused: a request with 413, a response with
    /// `.bodyTooLarge`.
    public var maxBodySize: Int
    /// What each read takes in, and each write gathers, at most.
    public var bufferSize: Int

    public init(maxHeaderSize: Int = 32 * 1024, maxHeaderCount: Int = 100, maxTrailerSize: Int = 32 * 1024,
                maxBodySize: Int = 8 << 20, bufferSize: Int = 16 * 1024) {
        self.maxHeaderSize = maxHeaderSize
        self.maxHeaderCount = maxHeaderCount
        self.maxTrailerSize = maxTrailerSize
        self.maxBodySize = maxBodySize
        self.bufferSize = bufferSize
    }

    /// The decoders' share of it.
    public var limits: HTTP1Limits {
        HTTP1Limits(maxHeaderSize: maxHeaderSize, maxHeaderCount: maxHeaderCount, maxTrailerSize: maxTrailerSize)
    }
}

/// Requests from a byte stream, for a server: NIO's `HTTPRequestDecoder`.
///
/// Each request comes out as `.head`, any number of `.body` parts, then
/// `.end`, including one without a body. Several requests in a row
/// (pipelining) decode one after the other.
public struct HTTP1RequestDecoder: FrameDecoder, Sendable {
    public typealias Item = HTTPRequestPart

    public var limits: HTTP1Limits
    private var state = State.head(scanned: 0)

    private enum State {
        /// Bytes before `scanned` hold no end of the head.
        case head(scanned: Int)
        case body(BodyReader)
    }

    public init(limits: HTTP1Limits = .init()) {
        self.limits = limits
    }

    /// The next part, with how many bytes it used; nil if `bytes` doesn't
    /// hold it yet.
    public mutating func decodePart(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Item, consumed: Int)? {
        switch state {
        case .head(let scanned):
            // An empty line or two before a request is allowed (RFC 9112 2.2).
            var lead = 0
            while lead < bytes.count, bytes[lead] == cCR || bytes[lead] == cLF { lead += 1 }
            guard let end = findHeadEnd(bytes, from: max(lead, scanned)) else {
                if bytes.count - lead > limits.maxHeaderSize {
                    let lineEnded = bytes[lead...].contains(cLF)
                    throw lineEnded ? .headTooLarge : .uriTooLong
                }
                state = .head(scanned: max(lead, bytes.count - 2))
                return nil
            }
            if end - lead > limits.maxHeaderSize { throw .headTooLarge }
            let (head, framing) = try parsed { () throws(HTTP1ParseError) in
                try parseRequestHead(bytes, start: lead, end: end, maxFields: limits.maxHeaderCount)
            }
            let body: BodyReader.State
            if framing.transferEncoding == .chunked {
                body = .chunkHeader(afterData: false)
            } else if let n = framing.contentLength, n > 0 {
                body = .fixed(n)
            } else {
                body = .done
            }
            state = .body(BodyReader(state: body, maxFields: limits.maxHeaderCount, maxTrailerSize: limits.maxTrailerSize))
            return (.head(head), end)
        case .body(var reader):
            guard let (part, used) = try parsed({ () throws(HTTP1ParseError) in try reader.next(bytes) }) else { return nil }
            switch part {
            case .body(let b):
                state = .body(reader)
                return (.body(b), used)
            case .end(let trailers):
                state = .head(scanned: 0)
                return (.end(trailers), used)
            }
        }
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        do throws(HTTP1Error) { return try decodePart(bytes) } catch { throw error.codecError }
    }

    /// At end of stream: nil between requests, `.truncated` inside one.
    public mutating func decodePartAtEnd(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Item, consumed: Int)? {
        if let part = try decodePart(bytes) { return part }
        if case .head = state, !bytes.contains(where: { $0 != cCR && $0 != cLF }) { return nil }
        throw .truncated
    }

    public mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        do throws(HTTP1Error) { return try decodePartAtEnd(bytes) } catch { throw error.codecError }
    }
}

/// Responses from a byte stream, for a client: NIO's `HTTPResponseDecoder`.
///
/// Whether a response has a body depends on the request it answers (a
/// response to HEAD has none), so call `requestSent(_:)` for each request,
/// in order; responses without one are taken to answer a GET.
///
/// After a `101 Switching Protocols` (or a 2xx to CONNECT) it decodes
/// nothing more: the bytes after it belong to the new protocol.
public struct HTTP1ResponseDecoder: FrameDecoder, Sendable {
    public typealias Item = HTTPResponsePart

    public var limits: HTTP1Limits
    private var state = State.head(scanned: 0)
    private var methods: [HTTPMethod] = []
    /// Whether the connection can carry another exchange.
    public private(set) var isReusable = true

    private enum State {
        case head(scanned: Int)
        case body(BodyReader)
        case upgraded
    }

    public init(limits: HTTP1Limits = .init()) {
        self.limits = limits
    }

    /// Note a request sent, so its response is read the right way.
    public mutating func requestSent(_ method: HTTPMethod) {
        methods.append(method)
    }

    public mutating func decodePart(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Item, consumed: Int)? {
        switch state {
        case .upgraded:
            return nil
        case .head(let scanned):
            guard let end = findHeadEnd(bytes, from: scanned) else {
                if bytes.count > limits.maxHeaderSize { throw .headTooLarge }
                state = .head(scanned: max(0, bytes.count - 2))
                return nil
            }
            if end > limits.maxHeaderSize { throw .headTooLarge }
            let (head, framing) = try parsed { () throws(HTTP1ParseError) in
                try parseResponseHead(bytes, start: 0, end: end, maxFields: limits.maxHeaderCount)
            }
            let status = head.status
            // An interim response comes before the real one to the same request.
            let interim = status < 200 && status != 101
            let method = interim ? (methods.first ?? .get) : (methods.isEmpty ? .get : methods.removeFirst())
            let body: BodyReader.State
            if status == 101 || (method == .connect && status / 100 == 2) {
                body = .done
                isReusable = false
            } else if interim || status == 204 || status == 304 || method == .head {
                body = .done
            } else {
                switch framing.transferEncoding {
                case .chunked:
                    body = .chunkHeader(afterData: false)
                case .notChunked:
                    body = .untilClose
                case .none:
                    if let n = framing.contentLength {
                        body = n > 0 ? .fixed(n) : .done
                    } else {
                        body = .untilClose
                    }
                case .chunkedOverOther:
                    throw .unsupportedTransferEncoding
                }
            }
            if case .untilClose = body { isReusable = false }
            if !head.keepAlive { isReusable = false }
            state = .body(BodyReader(state: body, maxFields: limits.maxHeaderCount, maxTrailerSize: limits.maxTrailerSize))
            return (.head(head), end)
        case .body(var reader):
            guard let (part, used) = try parsed({ () throws(HTTP1ParseError) in try reader.next(bytes) }) else { return nil }
            switch part {
            case .body(let b):
                state = .body(reader)
                return (.body(b), used)
            case .end(let trailers):
                state = isReusable ? .head(scanned: 0) : .upgraded
                return (.end(trailers), used)
            }
        }
    }

    public mutating func decode(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        do throws(HTTP1Error) { return try decodePart(bytes) } catch { throw error.codecError }
    }

    /// At end of stream: ends a body that runs to the close; nil between
    /// responses; `.truncated` inside one.
    public mutating func decodePartAtEnd(_ bytes: UnsafeRawBufferPointer) throws(HTTP1Error) -> (item: Item, consumed: Int)? {
        if let part = try decodePart(bytes) { return part }
        switch state {
        case .upgraded:
            return nil
        case .head:
            if bytes.isEmpty { return nil }
        case .body(let reader):
            if case .untilClose = reader.state {
                state = .upgraded
                return (.end(nil), 0)
            }
        }
        throw .truncated
    }

    public mutating func decodeAtEnd(_ bytes: UnsafeRawBufferPointer) throws(CodecError) -> (item: Item, consumed: Int)? {
        do throws(HTTP1Error) { return try decodePartAtEnd(bytes) } catch { throw error.codecError }
    }
}

/// How the body being written is framed.
private enum BodyWriter: Sendable {
    /// No body may follow.
    case none
    /// This many bytes still to come.
    case fixed(Int)
    case chunked
    /// Written as they are: a body that runs to the close, or a tunnel.
    case raw

    mutating func body(_ bytes: [UInt8], into buffer: inout IOBuffer) throws(HTTP1Error) {
        switch self {
        case .none:
            if !bytes.isEmpty { throw .bodyNotAllowed }
        case .fixed(let n):
            guard bytes.count <= n else { throw .contentLengthMismatch }
            self = .fixed(n - bytes.count)
            bytes.withUnsafeBytes { buffer.append($0) }
        case .chunked:
            guard !bytes.isEmpty else { return }
            buffer.appendHex(bytes.count)
            buffer.append("\r\n")
            bytes.withUnsafeBytes { buffer.append($0) }
            buffer.append("\r\n")
        case .raw:
            bytes.withUnsafeBytes { buffer.append($0) }
        }
    }

    mutating func end(_ trailers: HTTPFields?, into buffer: inout IOBuffer) throws(HTTP1Error) {
        switch self {
        case .fixed(let n) where n != 0:
            throw .contentLengthMismatch
        case .chunked:
            buffer.append("0\r\n")
            if let trailers { try buffer.appendFields(trailers, final: false) }
            buffer.append("\r\n")
        default:
            break
        }
        self = .none
    }
}

/// Responses to a byte stream, for a server: NIO's `HTTPResponseEncoder`.
///
/// A response with neither Content-Length nor Transfer-Encoding is sent
/// chunked (HTTP/1.1) or to the close (HTTP/1.0). Call `requestReceived(_:)`
/// for each request, in order, so a response to HEAD is sent without a body.
public struct HTTP1ResponseEncoder: FrameEncoder, Sendable {
    public typealias Item = HTTPResponsePart

    private var methods: [HTTPMethod] = []
    private var body = BodyWriter.none

    public init() {}

    /// Note a request answered, in order.
    public mutating func requestReceived(_ method: HTTPMethod) {
        methods.append(method)
    }

    public mutating func encodePart(_ part: Item, into buffer: inout IOBuffer) throws(HTTP1Error) {
        switch part {
        case .head(let head):
            let status = head.status
            let interim = status < 200 && status != 101
            let method = interim ? (methods.first ?? .get) : (methods.isEmpty ? .get : methods.removeFirst())
            guard (100...999).contains(status), head.reason.utf8.allSatisfy(isFieldValueChar) else { throw .invalidField }
            buffer.append(head.version.description)
            buffer.append(" ")
            buffer.appendDecimal(status)
            buffer.append(" ")
            buffer.append(head.reason)
            buffer.append("\r\n")
            try buffer.appendFields(head.fields, final: false)
            if interim || status == 204 || status == 304 || method == .head {
                body = .none
            } else if status == 101 || (method == .connect && status / 100 == 2) {
                body = .raw
            } else {
                body = try framing(head.fields, head.version, &buffer, response: true)
            }
            buffer.append("\r\n")
        case .body(let bytes):
            try body.body(bytes, into: &buffer)
        case .end(let trailers):
            try body.end(trailers, into: &buffer)
        }
    }

    public mutating func encode(_ item: Item, into buffer: inout IOBuffer) throws(CodecError) {
        do throws(HTTP1Error) { try encodePart(item, into: &buffer) } catch { throw error.codecError }
    }
}

/// Requests to a byte stream, for a client: NIO's `HTTPRequestEncoder`.
///
/// A request with neither Content-Length nor Transfer-Encoding is sent
/// chunked, except a GET, HEAD, DELETE, OPTIONS, TRACE or CONNECT, which
/// are taken to have no body.
public struct HTTP1RequestEncoder: FrameEncoder, Sendable {
    public typealias Item = HTTPRequestPart

    private var body = BodyWriter.none

    public init() {}

    public mutating func encodePart(_ part: Item, into buffer: inout IOBuffer) throws(HTTP1Error) {
        switch part {
        case .head(let head):
            guard !head.method.rawValue.isEmpty, head.method.rawValue.utf8.allSatisfy(isTokenChar),
                  !head.target.isEmpty, head.target.utf8.allSatisfy({ $0 > cSP && $0 != 0x7F })
            else { throw .invalidField }
            buffer.append(head.method.rawValue)
            buffer.append(" ")
            buffer.append(head.target)
            buffer.append(" ")
            buffer.append(head.version.description)
            buffer.append("\r\n")
            try buffer.appendFields(head.fields, final: false)
            let bodiless: [HTTPMethod] = [.get, .head, .delete, .options, .trace, .connect]
            if !head.fields.contains("content-length") && !head.fields.contains("transfer-encoding")
                && bodiless.contains(head.method) {
                body = head.method == .connect ? .raw : .none
            } else {
                body = try framing(head.fields, head.version, &buffer, response: false)
            }
            buffer.append("\r\n")
        case .body(let bytes):
            try body.body(bytes, into: &buffer)
        case .end(let trailers):
            if case .raw = body { return } // a CONNECT tunnel stays open
            try body.end(trailers, into: &buffer)
        }
    }

    public mutating func encode(_ item: Item, into buffer: inout IOBuffer) throws(CodecError) {
        do throws(HTTP1Error) { try encodePart(item, into: &buffer) } catch { throw error.codecError }
    }
}

/// The framing `fields` give a body, adding Transfer-Encoding (or for
/// HTTP/1.0 responses, Connection: close) when they give none.
private func framing(_ fields: HTTPFields, _ version: HTTPVersion, _ buffer: inout IOBuffer,
                     response: Bool) throws(HTTP1Error) -> BodyWriter {
    if let te = fields["transfer-encoding"] {
        guard fields.values(for: "transfer-encoding").count == 1, !fields.contains("content-length"),
              te.lowercased().split(separator: ",").last?.trimmingSpaces == "chunked"
        else { throw .invalidField }
        return .chunked
    }
    if let cl = fields["content-length"] {
        guard let n = Int(cl), n >= 0, fields.values(for: "content-length").allSatisfy({ $0 == cl })
        else { throw .invalidField }
        return .fixed(n)
    }
    if version.minor >= 1 {
        buffer.append("transfer-encoding: chunked\r\n")
        return .chunked
    }
    if response {
        // An HTTP/1.0 response: its end is the close.
        if !fields.containsToken("close", in: "connection") { buffer.append("connection: close\r\n") }
        return .raw
    }
    throw .lengthRequired
}

extension Substring {
    fileprivate var trimmingSpaces: Substring {
        var s = self
        while s.first == " " || s.first == "\t" { s.removeFirst() }
        while s.last == " " || s.last == "\t" { s.removeLast() }
        return s
    }
}

extension IOBuffer {
    mutating func appendDecimal(_ n: Int) {
        append(String(n))
    }

    mutating func appendHex(_ n: Int) {
        append(String(n, radix: 16))
    }

    /// Field lines, checked so no name or value can end the field early,
    /// then the empty line if `final`.
    mutating func appendFields(_ fields: HTTPFields, final: Bool = true) throws(HTTP1Error) {
        for i in 0..<fields.count {
            let ok = fields.withRaw(i) { name, value in
                guard !name.isEmpty, name.allSatisfy(isTokenChar), value.allSatisfy(isFieldValueChar),
                      value.first != cSP, value.first != cHT, value.last != cSP, value.last != cHT
                else { return false }
                append(name)
                append(": ")
                append(value)
                append("\r\n")
                return true
            }
            if !ok { throw .invalidField }
        }
        if final { append("\r\n") }
    }
}

/// The parser's result, its refusal as an `HTTP1Error`.
@inline(__always)
private func parsed<T>(_ body: () throws(HTTP1ParseError) -> T) throws(HTTP1Error) -> T {
    do { return try body() } catch { throw HTTP1Error(error) }
}
